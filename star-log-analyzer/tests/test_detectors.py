import csv
import io
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from detectors import (InputError, parse_csv, analyze, detect_bruteforce,
                       detect_offhours, detect_traffic, KST, MAX_CSV_BYTES)

HEADER='timestamp,event_type,user,src_ip,bytes\n'
def rows(lines):
    return parse_csv((HEADER+'\n'.join(lines)+'\n').encode())

class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.sample=parse_csv((Path(__file__).resolve().parents[1]/'samples/sample_logs.csv').read_bytes())

    def test_sample_three_rules(self):
        result=analyze(self.sample)
        self.assertEqual(result['total_events'],11)
        self.assertEqual(result['total_alerts'],3)
        self.assertEqual(result['by_rule'],{'BRUTE_FORCE':1,'OFFHOUR_LOGIN':1,'TRAFFIC_SPIKE':1})
    def test_only_one_bruteforce_for_six_failures(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in range(6)]
        self.assertEqual(len(detect_bruteforce(rows(lines))),1)
    def test_bruteforce_needs_five(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in range(4)]
        self.assertEqual(detect_bruteforce(rows(lines)),[])
    def test_bruteforce_same_user_different_ip(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.{1 if i%2 else 2},' for i in range(7)]
        self.assertEqual(detect_bruteforce(rows(lines)),[])
    def test_bruteforce_time_boundary_inclusive(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in (0,1,2,3,5)]
        self.assertEqual(len(detect_bruteforce(rows(lines))),1)
    def test_bruteforce_more_than_five_minute_does_not_count(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in (0,1,2,3,6)]
        self.assertEqual(detect_bruteforce(rows(lines)),[])
    def test_bruteforce_separate_groups(self):
        lines=[f'2026-11-06T11:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in range(5)]
        lines += [f'2026-11-06T12:0{i}:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,' for i in range(5)]
        self.assertEqual(len(detect_bruteforce(rows(lines))),2)
    def test_offhours_in_kst(self):
        events=rows(['2026-11-05T17:00:00Z,LOGIN_SUCCESS,user01,192.0.2.1,',
                     '2026-11-05T22:00:00Z,LOGIN_SUCCESS,user01,192.0.2.1,'])
        self.assertEqual(len(detect_offhours(events)),1)
    def test_offhours_0559_and_0600(self):
        events=rows(['2026-11-06T05:59:00+09:00,LOGIN_SUCCESS,user01,192.0.2.1,',
                     '2026-11-06T06:00:00+09:00,LOGIN_SUCCESS,user01,192.0.2.1,'])
        self.assertEqual(len(detect_offhours(events)),1)
    def test_naive_date_assumes_kst(self):
        events=rows(['2026-11-06T02:15:00,LOGIN_SUCCESS,user01,192.0.2.1,'])
        self.assertEqual(len(detect_offhours(events)),1)
    def test_traffic_baseline_requires_three(self):
        events=rows(['2026-11-06T08:00:00+09:00,TRAFFIC,user01,192.0.2.1,100',
                     '2026-11-06T08:05:00+09:00,TRAFFIC,user01,192.0.2.1,100',
                     '2026-11-06T08:10:00+09:00,TRAFFIC,user01,192.0.2.1,1000'])
        self.assertEqual(detect_traffic(events),[])
    def test_traffic_exactly_double_not_alert(self):
        events=rows([f'2026-11-06T08:{5*i:02d}:00+09:00,TRAFFIC,user01,192.0.2.1,{200 if i==3 else 100}' for i in range(4)])
        self.assertEqual(detect_traffic(events),[])
    def test_traffic_just_over_double_alert(self):
        events=rows([f'2026-11-06T08:{5*i:02d}:00+09:00,TRAFFIC,user01,192.0.2.1,{201 if i==3 else 100}' for i in range(4)])
        self.assertEqual(len(detect_traffic(events)),1)
    def test_traffic_zero_baseline_is_deferred(self):
        events=rows([f'2026-11-06T08:{5*i:02d}:00+09:00,TRAFFIC,user01,192.0.2.1,{900 if i==3 else 0}' for i in range(4)])
        self.assertEqual(detect_traffic(events),[])
    def test_normal_sample_no_alerts(self):
        events=rows(['2026-11-06T09:00:00+09:00,LOGIN_SUCCESS,user01,192.0.2.1,',
                     '2026-11-06T09:02:00+09:00,LOGIN_FAILURE,user01,192.0.2.1,',
                     '2026-11-06T09:05:00+09:00,TRAFFIC,user01,192.0.2.1,1000'])
        self.assertEqual(analyze(events)['total_alerts'],0)
    def test_empty_content(self):
        with self.assertRaises(InputError): parse_csv(b'')
    def test_missing_column(self):
        with self.assertRaises(InputError): parse_csv(b'timestamp,user\nx,y\n')
    def test_bad_date(self):
        with self.assertRaises(InputError): rows(['bad-date,LOGIN_SUCCESS,u,192.0.2.1,'])
    def test_negative_bytes(self):
        with self.assertRaises(InputError): rows(['2026-11-06T08:00:00+09:00,TRAFFIC,u,192.0.2.1,-1'])
    def test_missing_traffic_bytes(self):
        with self.assertRaises(InputError): rows(['2026-11-06T08:00:00+09:00,TRAFFIC,u,192.0.2.1,'])
    def test_invalid_ip(self):
        with self.assertRaises(InputError): rows(['2026-11-06T08:00:00+09:00,LOGIN_SUCCESS,u,999.9.9.9,'])
    def test_duplicate_columns(self):
        with self.assertRaises(InputError): parse_csv(b'timestamp,timestamp,event_type,user,src_ip,bytes\n1,1,1,1,1,1\n')
    def test_extra_field(self):
        with self.assertRaises(InputError): parse_csv((HEADER+'2026-11-06T08:00:00+09:00,TRAFFIC,u,192.0.2.1,100,EXTRA\n').encode())
    def test_utf8_bom(self):
        self.assertEqual(len(parse_csv(b'\xef\xbb\xbf'+(HEADER+'2026-11-06T08:00:00+09:00,TRAFFIC,u,192.0.2.1,100\n').encode())),1)
    def test_size_limit(self):
        with self.assertRaises(InputError): parse_csv(b'a' * (MAX_CSV_BYTES+1))
    def test_csv_fields_containing_markup_are_safe_data(self):
        events=rows(['2026-11-06T08:00:00+09:00,LOGIN_SUCCESS,<img src=x>,192.0.2.1,'])
        self.assertEqual(events[0].user,'<img src=x>')

if __name__=='__main__': unittest.main()
