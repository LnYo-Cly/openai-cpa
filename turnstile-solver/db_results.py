import time
import asyncio

# 内存数据库，用于临时存储验证码结果
results_db = {}

async def init_db():
    pass

async def save_result(task_id, task_type, data):
    results_db[task_id] = data

async def load_result(task_id):
    return results_db.get(task_id)

async def cleanup_old_results(days_old=7):
    now = time.time()
    to_delete = []
    for tid, res in results_db.items():
        if isinstance(res, dict) and now - res.get('createTime', now) > days_old * 86400:
            to_delete.append(tid)
    for tid in to_delete:
        del results_db[tid]
    return len(to_delete)
