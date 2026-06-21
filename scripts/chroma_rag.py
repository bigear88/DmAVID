"""ChromaDB helper — DmAVID iterative Blue Team knowledge base.

Collection:  dmavid_blue_team_iter
Path:        data/chroma_kb/
Embedding:   text-embedding-3-small (OpenAI)
"""
import os
import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

BASE_DIR = "/home/curtis/DmAVID"
CHROMA_PATH = os.path.join(BASE_DIR, "data", "chroma_kb")
COLLECTION_NAME = "dmavid_blue_team_iter"

def _get_collection():
    ef = OpenAIEmbeddingFunction(
        api_key=os.environ["OPENAI_API_KEY"],
        model_name="text-embedding-3-small",
    )
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    return client.get_or_create_collection(COLLECTION_NAME, embedding_function=ef)


def write_blue_team_to_chroma(entries: list) -> int:
    """Vectorize Blue Team knowledge entries and upsert into ChromaDB.

    Returns the number of new documents inserted.
    """
    if not entries:
        return 0
    try:
        col = _get_collection()
        existing_ids = set(col.get(include=[])["ids"])

        docs, ids, metas = [], [], []
        for i, e in enumerate(entries):
            uid = f"bt_{e.get('category', 'unknown')}_{e.get('title', str(i)).replace(' ', '_')[:40]}"
            # Use a stable suffix to avoid duplicate IDs across rounds
            uid = uid + f"_{abs(hash(e.get('description', ''))) % 100000:05d}"
            if uid in existing_ids:
                continue

            text = " | ".join(filter(None, [
                e.get("title", ""),
                e.get("category", ""),
                e.get("description", ""),
                e.get("generalized_pattern", ""),
                e.get("detection_indicators", ""),
                e.get("mitigation_strategy", ""),
                e.get("safe_pattern", ""),
            ]))
            docs.append(text[:4096])  # ChromaDB doc length cap
            ids.append(uid)
            metas.append({
                "category":   str(e.get("category", "")),
                "title":      str(e.get("title", "")),
                "mitigation": str(e.get("mitigation_strategy", ""))[:500],
            })

        if docs:
            col.add(documents=docs, ids=ids, metadatas=metas)
        return len(docs)
    except Exception as exc:
        print(f"[chroma_rag] write_blue_team_to_chroma error: {exc}")
        return 0


def query_chroma_context(code_snippet: str, n_results: int = 3) -> str:
    """Query ChromaDB for Blue Team patterns semantically similar to the code.

    Returns a formatted string ready to inject into the RAG context,
    or an empty string if the collection is empty or an error occurs.
    """
    try:
        col = _get_collection()
        count = col.count()
        if count == 0:
            return ""
        k = min(n_results, count)
        results = col.query(
            query_texts=[code_snippet[:2000]],
            n_results=k,
            include=["documents", "metadatas", "distances"],
        )
        parts = ["\n=== CHROMADB LEARNED PATTERNS (Blue Team iterative KB) ==="]
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        ):
            similarity = 1.0 - dist  # cosine distance → similarity
            if similarity < 0.10:    # skip very dissimilar hits
                continue
            cat = meta.get("category", "")
            title = meta.get("title", "")
            mit = meta.get("mitigation", "")
            parts.append(
                f"  [{cat.upper()}] {title} (sim={similarity:.2f})\n"
                f"  Context: {doc[:300]}\n"
                + (f"  Mitigation: {mit[:200]}\n" if mit else "")
            )
        if len(parts) == 1:  # only the header, no usable hits
            return ""
        return "\n".join(parts) + "\n"
    except Exception as exc:
        print(f"[chroma_rag] query_chroma_context error: {exc}")
        return ""
