#!/usr/bin/env python3
"""
Build Vector Knowledge Base for RAG-Enhanced Vulnerability Detection.

This script:
1. Loads structured vulnerability knowledge entries from JSON.
2. Uses OpenAI text-embedding-3-small to vectorize each entry.
3. Stores embeddings in a ChromaDB persistent collection for semantic retrieval.

The resulting vector store is consumed by 05_run_llm_rag.py for RAG-enhanced detection.

Usage:
    python build_knowledge_base.py [--reset]

    --reset    Delete existing collection and rebuild from scratch.
"""

import os
import sys
import json
import argparse
from datetime import datetime

import chromadb
from chromadb.config import Settings
from openai import OpenAI

# ── Paths ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)  # project root
KNOWLEDGE_FILE = os.path.join(SCRIPT_DIR, "knowledge", "vulnerability_knowledge.json")
CHROMA_DIR = os.path.join(BASE_DIR, "data", "chroma_kb")

# ── Constants ──────────────────────────────────────────────────────
COLLECTION_NAME = "vuln_knowledge"
EMBEDDING_MODEL = "text-embedding-3-small"
EMBEDDING_DIM = 1536  # text-embedding-3-small default dimension


def load_knowledge(filepath: str) -> list[dict]:
    """Load vulnerability knowledge entries from JSON."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    entries = data["entries"]
    print(f"  Loaded {len(entries)} knowledge entries from {os.path.basename(filepath)}")
    print(f"  Categories: {', '.join(data['metadata']['categories'])}")
    return entries


def entry_to_document(entry: dict) -> str:
    """Convert a single knowledge entry into a document string for embedding.

    The document is structured to maximize semantic retrieval quality:
    we concatenate the most informative fields into a single string
    so the embedding captures vulnerability semantics, patterns, and mitigations.
    """
    parts = [
        f"[{entry['category'].upper()}] {entry['title']}",
        f"Description: {entry['description']}",
        f"Vulnerability Pattern: {entry.get('vulnerability_pattern', 'N/A')}",
        f"Safe Pattern: {entry.get('safe_pattern', 'N/A')}",
        f"Mitigation: {entry.get('mitigation', 'N/A')}",
        f"Severity: {entry.get('severity', 'Unknown')}",
    ]
    if entry.get("real_world_case"):
        parts.append(f"Real-world case: {entry['real_world_case']}")
    if entry.get("keywords"):
        parts.append(f"Keywords: {', '.join(entry['keywords'])}")
    return "\n".join(parts)


def compute_embeddings(texts: list[str], client: OpenAI) -> list[list[float]]:
    """Compute embeddings for a list of texts using OpenAI API.

    Uses batch API for efficiency (max 2048 inputs per request).
    """
    print(f"  Computing embeddings for {len(texts)} documents via {EMBEDDING_MODEL}...")

    # OpenAI embedding API supports batch requests
    batch_size = 100
    all_embeddings = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i : i + batch_size]
        response = client.embeddings.create(
            model=EMBEDDING_MODEL,
            input=batch,
        )
        batch_embeddings = [item.embedding for item in response.data]
        all_embeddings.extend(batch_embeddings)
        print(f"    Batch {i // batch_size + 1}: embedded {len(batch)} documents "
              f"(dim={len(batch_embeddings[0])})")

    return all_embeddings


def build_collection(
    entries: list[dict],
    embeddings: list[list[float]],
    chroma_dir: str,
    reset: bool = False,
) -> chromadb.Collection:
    """Create or update the ChromaDB collection with vulnerability knowledge."""

    # Initialize persistent ChromaDB client
    client = chromadb.PersistentClient(path=chroma_dir)

    # Optionally delete existing collection
    if reset:
        try:
            client.delete_collection(COLLECTION_NAME)
            print(f"  Deleted existing collection '{COLLECTION_NAME}'")
        except Exception:
            pass

    # Create collection (or get existing one)
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={
            "description": "DeFi Smart Contract Vulnerability Knowledge Base",
            "embedding_model": EMBEDDING_MODEL,
            "hnsw:space": "cosine",  # Use cosine similarity for semantic search
        },
    )

    # Prepare data for ChromaDB upsert
    ids = [entry["id"] for entry in entries]
    documents = [entry_to_document(entry) for entry in entries]
    metadatas = [
        {
            "category": entry["category"],
            "title": entry["title"],
            "severity": entry.get("severity", "Unknown"),
            "swc_id": entry.get("swc_id", "N/A"),
            "description": entry["description"][:500],  # ChromaDB metadata size limit
            "vulnerability_pattern": entry.get("vulnerability_pattern", "")[:500],
            "safe_pattern": entry.get("safe_pattern", "")[:500],
            "mitigation": entry.get("mitigation", "")[:500],
            "real_world_case": entry.get("real_world_case", "")[:200],
            "keywords": ", ".join(entry.get("keywords", [])),
        }
        for entry in entries
    ]

    # Upsert all entries (idempotent)
    collection.upsert(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
    )

    print(f"  Collection '{COLLECTION_NAME}': {collection.count()} entries stored")
    return collection


def verify_collection(collection: chromadb.Collection, openai_client: OpenAI = None):
    """Run a few sample queries to verify the knowledge base works correctly."""
    print("\n  Verification queries:")

    test_queries = [
        ("reentrancy external call", "Should match reentrancy entries"),
        ("flash loan price manipulation", "Should match flash loan / oracle entries"),
        ("integer overflow SafeMath", "Should match integer overflow entries"),
        ("access control onlyOwner modifier", "Should match access control entries"),
    ]

    for query_text, expected in test_queries:
        # Use OpenAI embeddings for query to match stored 1536-dim vectors
        query_embedding = compute_embeddings([query_text], openai_client)
        results = collection.query(
            query_embeddings=query_embedding,
            n_results=3,
        )
        top_ids = results["ids"][0]
        top_cats = [m["category"] for m in results["metadatas"][0]]
        distances = results["distances"][0] if results.get("distances") else ["N/A"] * 3
        print(f"    Query: '{query_text}'")
        print(f"      Expected: {expected}")
        print(f"      Top-3: {top_ids} (categories: {top_cats})")
        if distances != ["N/A"] * 3:
            print(f"      Distances: {[round(d, 4) for d in distances]}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Build vulnerability knowledge vector database")
    parser.add_argument("--reset", action="store_true", help="Delete existing collection and rebuild")
    args = parser.parse_args()

    print("=" * 60)
    print("Build Vector Knowledge Base (ChromaDB + OpenAI Embeddings)")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print(f"Embedding Model: {EMBEDDING_MODEL}")
    print(f"ChromaDB Path: {CHROMA_DIR}")
    print("=" * 60)

    # Step 1: Load knowledge entries
    print("\n[1/4] Loading knowledge entries...")
    entries = load_knowledge(KNOWLEDGE_FILE)

    # Step 2: Prepare documents for embedding
    print("\n[2/4] Preparing documents for vectorization...")
    documents = [entry_to_document(entry) for entry in entries]
    avg_len = sum(len(d) for d in documents) / len(documents)
    print(f"  Average document length: {avg_len:.0f} characters")

    # Step 3: Compute embeddings
    print(f"\n[3/4] Computing embeddings via OpenAI {EMBEDDING_MODEL}...")
    openai_client = OpenAI()
    embeddings = compute_embeddings(documents, openai_client)
    print(f"  Total embeddings: {len(embeddings)} × {len(embeddings[0])} dimensions")

    # Step 4: Store in ChromaDB
    print(f"\n[4/4] Storing in ChromaDB ({CHROMA_DIR})...")
    os.makedirs(CHROMA_DIR, exist_ok=True)
    collection = build_collection(entries, embeddings, CHROMA_DIR, reset=args.reset)

    # Verification
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)
    verify_collection(collection, openai_client)

    # Summary
    print("=" * 60)
    print("BUILD COMPLETE")
    print(f"  Entries: {collection.count()}")
    print(f"  Collection: {COLLECTION_NAME}")
    print(f"  Storage: {CHROMA_DIR}")
    print(f"  Embedding Model: {EMBEDDING_MODEL}")
    print("=" * 60)


if __name__ == "__main__":
    main()
