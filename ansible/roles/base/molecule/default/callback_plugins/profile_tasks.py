# molecule/default/callback_plugins/profile_tasks.py
from ansible.plugins.callback import CallbackBase
import time

class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'profile_tasks'
    CALLBACK_NEEDS_WHITELIST = False

    def __init__(self):
        super(CallbackModule, self).__init__()
        self.stats = {}

    def v2_runner_on_ok(self, result, **kwargs):
        task_name = result._task.get_name()
        task_time = time.time() - self.start_time
        if task_name not in self.stats:
            self.stats[task_name] = []
        self.stats[task_name].append(task_time)

    def v2_playbook_on_task_start(self, task, is_conditional):
        self.start_time = time.time()

    def v2_playbook_on_stats(self, stats):
        for task_name, timings in self.stats.items():
            total_time = sum(timings)
            average_time = total_time / len(timings)
            print(f"Task: {task_name} - Total Time: {total_time:.2f}s, Average Time: {average_time:.2f}s")
