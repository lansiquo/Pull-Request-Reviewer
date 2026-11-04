"""Strict normalized queue identifiers shared by webhook and push reconciliation."""
import re


def identifier(value):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}",value) or value in {'.','..'}:
        raise ValueError('Invalid repository identifier')
    return value


def sha(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-fA-F]{40}',value):
        raise ValueError('Invalid commit SHA')
    return value.lower()


def branch(value):
    if not isinstance(value,str) or not 1<=len(value)<=255 or any(ord(c)<33 or ord(c)==127 for c in value):
        raise ValueError('Invalid branch')
    if any(c in value for c in ('..','@{','\\','~','^',':','?','*','[')) or value.endswith(('/', '.')) or value.startswith('/'):
        raise ValueError('Invalid branch')
    if any(not part or part.startswith('.') or part.endswith('.lock') for part in value.split('/')):
        raise ValueError('Invalid branch')
    return value


def pr_job(pr, number, installation):
    base=pr['base'];head=pr['head']
    number=int(number);installation=int(installation)
    if number<=0 or installation<0:raise ValueError('Invalid identifier')
    return dict(base_owner=identifier(base['repo']['owner']['login']),base_repo=identifier(base['repo']['name']),
        head_owner=identifier(head['repo']['owner']['login']),head_repo=identifier(head['repo']['name']),
        pr=number,head_sha=sha(head['sha']),installation_id=installation,
        base_sha=sha(base['sha']),base_ref=branch(base['ref']) if base.get('ref') is not None else None)
