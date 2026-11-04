"""Local queue inspection and explicit failed-job recovery; no GitHub calls."""
import argparse
import json
from pathlib import Path
from job_store import JobStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', required=True, type=Path)
    parser.add_argument('--quarantine-legacy', action='store_true', help='With services stopped and backup verified, quarantine jobs lacking base context')
    parser.add_argument('--retry', metavar='JOB_ID', help='Explicitly requeue one failed job after fixing its cause')
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error('Queue database does not exist')
    store = JobStore(args.db)
    if args.quarantine_legacy and args.retry:
        parser.error('Choose one mutation')
    if args.quarantine_legacy:
        print(json.dumps({'quarantined': store.quarantine_legacy()}))
    elif args.retry:
        print(json.dumps({'requeued': store.requeue_failed(args.retry), 'job_id': args.retry}))
    else:
        print(json.dumps(store.status(), indent=2))


if __name__ == '__main__':
    main()
