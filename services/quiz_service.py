import json
import os
import datetime
import random
import uuid

class QuizService:
    DATA_FILE = "data/quiz_db.json"
    PROGRESS_FILE = "data/user_progress.json"

    @staticmethod
    def load_quizzes():
        if not os.path.exists(QuizService.DATA_FILE):
            return []
        with open(QuizService.DATA_FILE, 'r') as f:
            data = json.load(f)
            return data.get("modules", [])

    @staticmethod
    def load_question_bank():
        if not os.path.exists(QuizService.DATA_FILE):
            return []
        with open(QuizService.DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "question_bank" in data and isinstance(data["question_bank"], list):
            return data["question_bank"]
        modules = data.get("modules", [])
        bank = []
        for m in modules:
            for q in m.get("questions", []):
                bank.append(
                    {
                        "id": q.get("id") or str(uuid.uuid4()),
                        "level": "Beginner",
                        "category": m.get("title", "General"),
                        "text": q.get("text"),
                        "options": q.get("options", []),
                        "correct": q.get("correct"),
                        "explanation": q.get("explanation", ""),
                        "example": q.get("example", ""),
                    }
                )
        return bank

    @staticmethod
    def list_levels():
        return ["Beginner", "Intermediate", "Advanced"]

    @staticmethod
    def list_categories():
        bank = QuizService.load_question_bank()
        categories = sorted(list({q.get("category", "General") for q in bank if q.get("category")}))
        return categories

    @staticmethod
    def sample_questions(level, count, categories=None, seed=None):
        bank = QuizService.load_question_bank()
        candidates = [q for q in bank if q.get("level") == level]
        if categories:
            categories_set = set(categories)
            candidates = [q for q in candidates if q.get("category") in categories_set]
        rng = random.Random(seed)
        rng.shuffle(candidates)
        return candidates[: int(count)]

    @staticmethod
    def save_result(username, module_id, score, total, passed, meta=None):
        progress = {}
        if os.path.exists(QuizService.PROGRESS_FILE):
            with open(QuizService.PROGRESS_FILE, 'r') as f:
                try:
                    progress = json.load(f)
                except:
                    progress = {}
        
        if username not in progress:
            progress[username] = []
            
        record = {
            "attempt_id": str(uuid.uuid4()),
            "module_id": module_id,
            "score": score,
            "total": total,
            "passed": passed,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "meta": meta or {}
        }
        
        progress[username].append(record)
        
        with open(QuizService.PROGRESS_FILE, 'w') as f:
            json.dump(progress, f, indent=4)
            
    @staticmethod
    def get_user_progress(username):
        if not os.path.exists(QuizService.PROGRESS_FILE):
            return []
        with open(QuizService.PROGRESS_FILE, 'r') as f:
            try:
                progress = json.load(f)
                return progress.get(username, [])
            except:
                return []

    @staticmethod
    def get_all_results():
        """For Admin Dashboard"""
        if not os.path.exists(QuizService.PROGRESS_FILE):
            return {}
        with open(QuizService.PROGRESS_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                return {}
