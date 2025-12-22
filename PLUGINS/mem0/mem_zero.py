import os

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"

from mem0 import Memory

from PLUGINS.Embeddings.CONFIG import EMBEDDINGS_SIZE
from PLUGINS.Embeddings.embeddings_qdrant import EmbeddingsAPI
from PLUGINS.LLM.llmapi import LLMAPI
from PLUGINS.Qdrant.qdrant import Qdrant
from PLUGINS.neo4j.CONFIG import NEO4J_URL, NEO4J_PASSWORD, NEO4J_USER


class MemZero(object):

    def __init__(self):
        # embeddings
        self.embeddings_model = EmbeddingsAPI.get_dense_model()

        # llm
        llm_api = LLMAPI()
        self.llm_model = llm_api.get_model(tag=["fast"])

        self.vector_store = Qdrant.get_client()

        config = {
            "reranker": {
                "provider": "huggingface",
                "config": {
                    "model": "BAAI/bge-reranker-v2-m3",
                    # "device": "cuda",
                    "device": "cpu"
                }
            },
            # "reranker": {
            #     "provider": "llm_reranker",
            #     "config": {
            #         "provider": "ollama",
            #         "model": "qwen3:30b-a3b",
            #         "ollama_base_url": "http://admin:passwordforollama@192.168.241.128:11434",
            #         "api_key": "ollama",
            #
            #     }
            # },
            "graph_store": {
                "provider": "neo4j",
                "config": {
                    "url": NEO4J_URL,
                    "username": NEO4J_USER,
                    "password": NEO4J_PASSWORD,
                }
            },
            "vector_store": {
                "provider": "qdrant",
                "config": {
                    "collection_name": "knowledge_mem0",
                    "client": self.vector_store,
                    "embedding_model_dims": EMBEDDINGS_SIZE,
                    "on_disk": True,
                }
            },
            "llm": {
                "provider": "langchain",
                "config": {
                    "model": self.llm_model,
                }
            },
            "embedder": {
                "provider": "langchain",
                "config": {
                    "model": self.embeddings_model,
                }
            },

        }

        self.memory = Memory.from_config(config)
        print("MemZero initialized.")

    def demo(self):
        conversation = [
            {"role": "user", "content": "10.198.125.16是安全部门的扫描器,可能会产生NDR告警,直接忽略"},
            {"role": "user", "content": "test@gmail.com是钓鱼模拟邮箱,如果用户上报的钓鱼邮件是这个邮箱,直接降低等级"},
        ]

        result_add = self.memory.add(conversation, user_id="demo-user")
        print(result_add)
        results = self.memory.search(
            "test@gmail.com需要安全部门封禁吗?",
            user_id="demo-user",
            limit=3,
            rerank=True,
        )
        for hit in results["results"]:
            print(hit)

    def delete(self):
        result_delete = self.memory.delete_all(user_id="demo-user")
        print(result_delete)


if __name__ == "__main__":
    mem0 = MemZero()
    mem0.demo()
    # mem0.delete()
