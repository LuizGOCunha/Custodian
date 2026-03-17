import subprocess
import csv
import io


def get_processes_by_ip(target_ip: str):
    result = subprocess.check_output("netstat -ano", text=True)

    process_names = set()

    for line in result.splitlines():
        if target_ip in line:
            parts = line.split()
            if len(parts) < 5:
                continue

            pid = parts[-1]

            try:
                task_output = subprocess.check_output(f'tasklist /FI "PID eq {pid}" /FO CSV /NH', text=True)

                reader = csv.reader(io.StringIO(task_output))
                row = next(reader)

                process_names.add(row[0])  # Only the image name

            except Exception:
                continue

    return list(process_names)


pass
