"""Flask HTTP wrapper around offline log analysis. No uploads are stored."""
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import RequestEntityTooLarge
from detectors import InputError, MAX_CSV_BYTES, analyze, parse_csv

ROOT=Path(__file__).resolve().parent
app=Flask(__name__)
app.config['MAX_CONTENT_LENGTH']=MAX_CSV_BYTES + 16384
app.json.ensure_ascii=False

@app.get('/')
def home():
    return render_template('index.html')

@app.get('/health')
def health():
    return jsonify(ok=True, service='log-at-a-glance')

@app.get('/sample.csv')
def sample():
    return send_file(ROOT/'samples'/'sample_logs.csv', mimetype='text/csv; charset=utf-8', as_attachment=True, download_name='sample_logs.csv')

@app.post('/api/analyze')
def analyze_api():
    try:
        if request.form.get('sample') == 'true':
            content=(ROOT/'samples'/'sample_logs.csv').read_bytes()
        else:
            up=request.files.get('file')
            if up is None:
                raise InputError('분석할 CSV 파일을 선택하거나 예시 로그를 불러와 주세요.')
            content=up.stream.read(MAX_CSV_BYTES+1)
        result=analyze(parse_csv(content))
        return jsonify(result)
    except InputError as exc:
        return jsonify(error=str(exc)), 400

@app.errorhandler(RequestEntityTooLarge)
def too_large(_):
    return jsonify(error='파일 크기가 너무 큽니다. 최대 256KB CSV만 분석할 수 있습니다.'),413

@app.errorhandler(404)
def not_found(_):
    return jsonify(error='요청한 페이지를 찾을 수 없습니다.'),404

if __name__=='__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
