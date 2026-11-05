'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const original=fs.readFileSync('index.html','utf8');
const server=fs.readFileSync('server/t08-app.cjs','utf8');
test('T01 public page and T08 private boundary coexist',()=>{
  for(const word of ['ONE PAGE INTRODUCTION','어떤 사람인가','내가 좋아하는 것','패스키로 잠근 나만의 공간'])assert.ok(original.includes(word));
  assert.ok(original.includes('id="t08-locked"'));
  assert.ok(original.includes('id="t08-unlocked" hidden'));
});
test('source does not disclose seeded notes',()=>{
  assert.ok(!original.includes('가상 데이터] 공개 소개 사이트'));
  assert.ok(!original.includes('가상 데이터] 오늘 잘한 점'));
  assert.ok(!original.includes('type="password"'));
});
test('server validates stored challenge and account ownership',()=>{
  assert.ok(server.includes('DELETE FROM t08_challenges'));
  assert.ok(server.includes('expectedChallenge:pending.challenge'));
  assert.ok(server.includes('verifyAuthenticationResponse'));
  assert.ok(server.includes('AND user_id=$2'));
});
