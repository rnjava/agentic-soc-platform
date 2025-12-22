import json
from typing import Annotated

from langchain_core.documents import Document

from PLUGINS.Embeddings.embeddings_qdrant import embedding_api_singleton_qdrant
from PLUGINS.SIRP.sirpapi import Knowledge
from PLUGINS.mem0.mem_zero import mem_zero_singleton


class KnowledgeAgent(object):

    @staticmethod
    def search(
            query: Annotated[
                str, "The search query, can be an entity (IP, Email, Domain) or a business concept/rule description or "
                     "anything you want to know from internal knowledge base."]
    ) -> Annotated[str, "A JSON string containing relevant knowledge entries, policies, and special handling instructions."]:
        """
        Search the internal knowledge base for specific entities, business-specific logic, SOPs, or historical context.
        """
        threshold = 0.8
        result_all = []
        docs_qdrant = embedding_api_singleton_qdrant.search_documents_with_rerank(collection_name=Knowledge.COLLECTION_NAME, query=query, k=10, top_n=3)
        for doc, score in docs_qdrant:
            doc: Document
            if score >= threshold:
                result_all.append(doc.page_content)
        print(docs_qdrant)
        result = mem_zero_singleton.search_mem(user_id=Knowledge.COLLECTION_NAME, query=query, limit=3)
        for one_record in result:
            id = one_record.get("id")
            score = one_record.get("score", 0)
            memory = one_record.get("memory", "")
            if score >= threshold:
                result_all.append(memory)
        print(result)
        return json.dumps(result_all, ensure_ascii=False)


if __name__ == "__main__":
    query = "test@gmail.com"
    result = KnowledgeAgent.search(query=query)
    print(result)