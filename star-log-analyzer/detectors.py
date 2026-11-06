"""Pure, offline educational detection rules. No data is persisted."""
from __future__ import annotations

import csv
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import StringIO
from ipaddress import ip_address
from typing import Any

KST = timezone(timedelta(hours=9))
REQUIRED_COLUMNS = ('timestamp', 'event_type', 'user', 'src_ip', 'bytes')
ALLOWED_EVENT_TYPES = {'LOGIN_FAILURE', 'LOGIN_SUCCESS', 'TRAFFIC'}
MAX_ROWS = 2000
MAX_CSV_BYTES = 256 * 1024


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    event_type: str
    user: str
    src_ip: str
    byte_count: int


def _display(dt: datetime) -> str:
    return dt.astimezone(KST).isoformat(timespec='seconds')


def parse_csv(content: bytes) -> list[Event]:
    if not content:
        raise InputError('CSV가 비어 있습니다. 예시 로그를 사용하거나 파일을 선택해 주세요.')
    if len(content) > MAX_CSV_BYTES:
        raise InputError('CSV 파일은 256KB 이하만 분석할 수 있습니다.')
    try:
        raw = content.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise InputError('CSV는 UTF-8 인코딩으로 저장해 주세요.') from exc
    try:
        reader = csv.DictReader(StringIO(raw, newline=''), strict=True)
        if reader.fieldnames is None:
            raise InputError('CSV의 첫 줄에 열 이름이 필요합니다.')
        names = [k.strip() for k in reader.fieldnames]
        if len(names) != len(set(names)):
            raise InputError('CSV에 중복된 열 이름이 있습니다.')
        missing = set(REQUIRED_COLUMNS) - set(names)
        if missing:
            raise InputError('필수 열 누락: ' + ', '.join(sorted(missing)))
        result = []
        for i, row in enumerate(reader, start=2):
            if i > MAX_ROWS + 1:
                raise InputError(f'최대 {MAX_ROWS:,}행까지 분석할 수 있습니다.')
            if None in row or any(v is None for v in row.values()):
                raise InputError(f'{i}행: 열 개수가 맞지 않습니다.')
            row = {k.strip(): v.strip() for k,v in row.items()}
            if all(not v for v in row.values()):
                continue
            try:
                raw_dt = row['timestamp'].replace('Z', '+00:00')
                dt = datetime.fromisoformat(raw_dt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=KST)
                dt = dt.astimezone(KST)
            except (ValueError, OverflowError):
                raise InputError(f'{i}행: ISO 8601 날짜/시간 형식이 아닙니다.')
            event_type = row['event_type'].upper()
            if event_type not in ALLOWED_EVENT_TYPES:
                raise InputError(f'{i}행: event_type은 LOGIN_FAILURE, LOGIN_SUCCESS, TRAFFIC만 허용합니다.')
            user = row['user']
            src_ip = row['src_ip']
            if not user or len(user) > 64 or any(ord(ch) < 32 for ch in user):
                raise InputError(f'{i}행: user는 1~64자의 일반 문자열이어야 합니다.')
            try:
                ip_address(src_ip)
            except ValueError:
                raise InputError(f'{i}행: src_ip 형식이 올바르지 않습니다.')
            raw_bytes = row['bytes']
            if raw_bytes:
                if not raw_bytes.isascii() or not raw_bytes.isdecimal() or len(raw_bytes) > 13:
                    raise InputError(f'{i}행: bytes는 0 이상의 정수여야 합니다.')
                count = int(raw_bytes)
                if count > 10**12:
                    raise InputError(f'{i}행: bytes 최대값을 초과했습니다.')
            else:
                count = 0
            if event_type == 'TRAFFIC' and not raw_bytes:
                raise InputError(f'{i}행: TRAFFIC에는 bytes 값이 필요합니다.')
            result.append(Event(dt, event_type, user, src_ip, count))
    except csv.Error as exc:
        raise InputError('CSV 문법 오류입니다. 따옴표와 쉼표를 확인해 주세요.') from exc
    if not result:
        raise InputError('분석할 로그 행이 없습니다.')
    return sorted(result, key=lambda x: x.timestamp)


def _alert(code: str, severity: str, dt: datetime, title: str, user: str, src_ip: str, evidence: str, detail: str) -> dict[str, Any]:
    return dict(code=code, severity=severity, timestamp=_display(dt), title=title,
                user=user, src_ip=src_ip, evidence=evidence, detail=detail)


def detect_bruteforce(events: list[Event]) -> list[dict]:
    """At least five failures in a rolling 5-minute period, grouped into incidents."""
    groups = defaultdict(list)
    for event in events:
        if event.event_type == 'LOGIN_FAILURE':
            groups[(event.user, event.src_ip)].append(event)
    alerts=[]
    duration=timedelta(minutes=5)
    for (user,ip), failures in groups.items():
        window=deque()
        active=None
        for failure in failures:
            while window and failure.timestamp-window[0].timestamp > duration:
                window.popleft()
            window.append(failure)
            if len(window) >= 5:
                if active is None or failure.timestamp-active['last'] > duration:
                    if active is not None: alerts.append(active)
                    active={'start':window[0].timestamp, 'last':failure.timestamp, 'count':len(window)}
                else:
                    active['last']=failure.timestamp
                    active['count']+=1
            elif active is not None and failure.timestamp-active['last'] > duration:
                alerts.append(active)
                active=None
        if active is not None: alerts.append(active)
        # The tuples are at user/IP level; turn them into visible incidents.
        for item in alerts:
            if 'user' not in item:
                item['user']=user; item['src_ip']=ip
    return [_alert('BRUTE_FORCE','높음',v['last'],'반복 로그인 실패',v['user'],v['src_ip'],
                   f'5분 내 실패 5회 이상 · 감지 구간 시작 {_display(v["start"])}',
                   '동일 사용자·IP에서 5분 내 로그인 실패가 연속 확인되었습니다. 실제 공격 확정은 아닙니다.') for v in alerts]


def detect_offhours(events: list[Event]) -> list[dict]:
    return [_alert('OFFHOUR_LOGIN','보통',e.timestamp,'심야 시간 성공 로그인',e.user,e.src_ip,
                   f'KST {e.timestamp.hour:02d}:{e.timestamp.minute:02d} 로그인 성공',
                   '00:00~05:59 KST 성공 로그인입니다. 교대 근무 등 정상 활동일 수 있습니다.')
            for e in events if e.event_type=='LOGIN_SUCCESS' and e.timestamp.astimezone(KST).hour < 6]


def detect_traffic(events: list[Event]) -> list[dict]:
    buckets=defaultdict(int)
    for e in events:
        if e.event_type == 'TRAFFIC':
            local=e.timestamp.astimezone(KST)
            key=local.replace(minute=(local.minute//5)*5, second=0, microsecond=0)
            buckets[key] += e.byte_count
    sorted_buckets=sorted(buckets.items())
    alerts=[]
    for i,(start,total) in enumerate(sorted_buckets):
        if i<3: continue
        prev=sorted_buckets[i-3:i]
        mean=sum(v for _,v in prev)/3
        if mean<=0: continue
        if total>2*mean:
            ratio=total/mean
            alerts.append(_alert('TRAFFIC_SPIKE','보통',start,'트래픽 급증','전체','—',
                f'현재 {total:,}B / 직전 유효 3구간 평균 {mean:,.0f}B · {ratio:.2f}배',
                '5분 합계가 직전 데이터 있는 3개 구간 평균의 2배를 초과했습니다. 비정상 트래픽 확정은 아닙니다.'))
    return alerts


def analyze(events: list[Event]) -> dict:
    alerts=detect_bruteforce(events)+detect_offhours(events)+detect_traffic(events)
    alerts.sort(key=lambda a:a['timestamp'], reverse=True)
    for n,a in enumerate(alerts,1): a['id']=f'EVT-{n:03d}'
    return {'total_events':len(events), 'total_alerts':len(alerts),
            'by_severity':{s:sum(x['severity']==s for x in alerts) for s in ('높음','보통','낮음')},
            'by_rule':{s:sum(x['code']==s for x in alerts) for s in ('BRUTE_FORCE','OFFHOUR_LOGIN','TRAFFIC_SPIKE')},
            'alerts':alerts,
            'notice':'교육용 3개 규칙 결과입니다. 이 결과는 실제 공격 사실이나 사이트의 안전을 확정하지 않습니다.'}
