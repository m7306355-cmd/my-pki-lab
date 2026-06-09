from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import subprocess
import os
import re
import json
import shutil
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'pki_lab_secret_key'

RSA_ROOT_DIR = r'D:\pki\RSA\Root'
RSA_INTERMEDIATE_DIR = r'D:\pki\RSA\Intermediate'
RSA_SERVER_DIR = r'D:\pki\RSA\Server'
SM2_ROOT_DIR = r'D:\pki\SM2\Root'
SM2_INTERMEDIATE_DIR = r'D:\pki\SM2\Intermediate'
SM2_SERVER_DIR = r'D:\pki\SM2\Server'
USER_DB = r'D:\pki\web\users.json'
RSA_USER_CERTS_DIR = r'D:\pki\RSA\UserCerts'
SM2_USER_CERTS_DIR = r'D:\pki\SM2\UserCerts'
GMSSL = r'D:\GmSSL\bin\gmssl.exe'

ADMIN_USER = 'admin'
ADMIN_PASS = 'admin123'

os.makedirs(RSA_USER_CERTS_DIR, exist_ok=True)
os.makedirs(SM2_USER_CERTS_DIR, exist_ok=True)

def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def parse_index(index_file):
    certs = []
    try:
        with open(index_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split('\t')
                if len(parts) < 6:
                    continue
                status = parts[0]
                expiry = parts[1]
                revoke_date = parts[2] if parts[2] else ''
                serial = parts[3]
                cn = parts[5]
                cn_match = re.search(r'CN=([^/,]+)', cn)
                cn = cn_match.group(1) if cn_match else 'Unknown'
                if status == 'V':
                    status_label = 'valid'
                    status_text = '有效'
                elif status == 'R':
                    status_label = 'revoked'
                    status_text = '已吊销'
                else:
                    status_label = 'expired'
                    status_text = '已过期'
                certs.append({
                    'status': status_label,
                    'status_text': status_text,
                    'expiry': expiry,
                    'revoke_date': revoke_date,
                    'serial': serial,
                    'cn': cn
                })
    except:
        pass
    return certs

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        org = request.form['org'].strip()
        users = load_users()
        if username in users:
            error = '用户名已存在'
        elif not username or not password:
            error = '用户名和密码不能为空'
        else:
            users[username] = {'password': password, 'org': org, 'certs': []}
            save_users(users)
            return redirect(url_for('user_login'))
    return render_template('register.html', error=error)

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        if username in users and users[username]['password'] == password:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            error = '用户名或密码错误'
    return render_template('user_login.html', error=error)

@app.route('/user_logout')
def user_logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not session.get('user'):
        return redirect(url_for('user_login'))
    username = session['user']
    users = load_users()
    user = users.get(username, {})
    certs = user.get('certs', [])
    return render_template('dashboard.html', username=username, certs=certs)

@app.route('/apply_cert', methods=['POST'])
def apply_cert():
    if not session.get('user'):
        return jsonify({'success': False, 'message': '未登录'})
    username = session['user']
    cn = request.form.get('cn', '').strip()
    password = request.form.get('password', '').strip()
    cert_type = request.form.get('cert_type', 'rsa').strip()
    if not cn:
        return jsonify({'success': False, 'message': 'CN 不能为空'})
    users = load_users()
    user = users[username]
    cert_name = f"{username}_{cn}_{cert_type}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
    if cert_type == 'sm2':
        user_certs_dir = SM2_USER_CERTS_DIR
    else:
        user_certs_dir = RSA_USER_CERTS_DIR
    key_file = os.path.join(user_certs_dir, cert_name + '.key')
    csr_file = os.path.join(user_certs_dir, cert_name + '.csr')
    cert_file = os.path.join(user_certs_dir, cert_name + '.pem')
    try:
        if cert_type == 'sm2':
            subprocess.run(
                [GMSSL, 'sm2keygen', '-pass', password, '-out', key_file],
                check=True, capture_output=True
            )
            subprocess.run(
                [GMSSL, 'reqgen',
                 '-C', 'CN', '-ST', 'Guangdong', '-L', 'Guangzhou',
                 '-O', 'Melissa PKI Lab', '-CN', cn,
                 '-key', key_file, '-pass', password,
                 '-out', csr_file],
                check=True, capture_output=True
            )
            result = subprocess.run(
                [GMSSL, 'reqsign',
                 '-in', csr_file,
                 '-days', '365',
                 '-cacert', os.path.join(SM2_INTERMEDIATE_DIR, 'intermediate-ca.pem'),
                 '-key', os.path.join(SM2_INTERMEDIATE_DIR, 'intermediate-ca.key'),
                 '-pass', password,
                 '-key_usage', 'digitalSignature',
                 '-key_usage', 'keyEncipherment',
                 '-out', cert_file],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                return jsonify({'success': False, 'message': 'SM2 证书签发失败，请检查中间 CA 口令'})
            serial_result = subprocess.run(
                [GMSSL, 'certparse', '-in', cert_file],
                capture_output=True, text=True
            )
            serial_match = re.search(r'serialNumber:\s+([0-9A-Fa-f]+)', serial_result.stdout)
            serial = serial_match.group(1) if serial_match else 'unknown'
        else:
            csr_conf = os.path.join(user_certs_dir, cert_name + '.cnf')
            subprocess.run(
                ['openssl', 'genrsa', '-out', key_file, '2048'],
                check=True, capture_output=True
            )
            with open(csr_conf, 'w') as f:
                f.write('[req]\n')
                f.write('distinguished_name = req_dn\n')
                f.write('prompt = no\n')
                f.write('[req_dn]\n')
                f.write('C = CN\n')
                f.write('O = Melissa PKI Lab\n')
                f.write(f'CN = {cn}\n')
            subprocess.run(
                ['openssl', 'req', '-new', '-key', key_file,
                 '-out', csr_file, '-config', csr_conf],
                check=True, capture_output=True
            )
            result = subprocess.run([
                'openssl', 'ca', '-batch',
                '-config', os.path.join(RSA_INTERMEDIATE_DIR, 'openssl.cnf'),
                '-in', csr_file,
                '-out', cert_file,
                '-days', '365',
                '-passin', f'pass:{password}'
            ], capture_output=True, text=True)
            if result.returncode != 0:
                return jsonify({'success': False, 'message': 'RSA 证书签发失败，请检查中间 CA 口令'})
            serial_result = subprocess.run(
                ['openssl', 'x509', '-in', cert_file, '-noout', '-serial'],
                capture_output=True, text=True
            )
            serial = serial_result.stdout.strip().replace('serial=', '')
        user['certs'].append({
            'cn': cn,
            'serial': serial,
            'cert_name': cert_name,
            'cert_type': cert_type.upper(),
            'issued_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'status': 'valid'
        })
        save_users(users)
        return jsonify({'success': True, 'message': f'{cert_type.upper()} 证书申请成功，序列号：{serial}'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'申请失败：{str(e)}'})

@app.route('/download_cert/<cert_name>')
def download_cert(cert_name):
    if not session.get('user'):
        return redirect(url_for('user_login'))
    rsa_file = os.path.join(RSA_USER_CERTS_DIR, cert_name + '.pem')
    sm2_file = os.path.join(SM2_USER_CERTS_DIR, cert_name + '.pem')
    if os.path.exists(rsa_file):
        return send_file(rsa_file, as_attachment=True, download_name=cert_name + '.pem')
    elif os.path.exists(sm2_file):
        return send_file(sm2_file, as_attachment=True, download_name=cert_name + '.pem')
    return '证书不存在', 404

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            error = '用户名或密码错误'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    rsa_certs = parse_index(os.path.join(RSA_INTERMEDIATE_DIR, 'index.txt'))
    root_certs = parse_index(os.path.join(RSA_ROOT_DIR, 'index.txt'))
    users = load_users()
    sm2_certs = []
    for username, user in users.items():
        for cert in user.get('certs', []):
            if cert.get('cert_type', '').upper() == 'SM2':
                sm2_certs.append({
                    'username': username,
                    'cn': cert['cn'],
                    'serial': cert['serial'],
                    'issued_at': cert['issued_at'],
                    'status': cert['status'],
                    'cert_name': cert['cert_name']
                })
    return render_template('admin.html',
                           root_certs=root_certs,
                           intermediate_certs=rsa_certs,
                           sm2_certs=sm2_certs,
                           users=users)

@app.route('/revoke', methods=['POST'])
def revoke():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': '未登录'})
    serial = request.form.get('serial')
    ca_type = request.form.get('ca_type')
    passwd = request.form.get('password')
    if ca_type == 'intermediate':
        cert_file = os.path.join(RSA_INTERMEDIATE_DIR, 'issued_certs', serial + '.pem')
        config = os.path.join(RSA_INTERMEDIATE_DIR, 'openssl.cnf')
        key_file = os.path.join(RSA_INTERMEDIATE_DIR, 'intermediate-ca.key')
        crl_out = os.path.join(RSA_INTERMEDIATE_DIR, 'crl', 'intermediate-ca.crl')
        cert_pem = os.path.join(RSA_INTERMEDIATE_DIR, 'intermediate-ca.pem')
    else:
        cert_file = os.path.join(RSA_ROOT_DIR, 'issued_certs', serial + '.pem')
        config = os.path.join(RSA_ROOT_DIR, 'openssl.cnf')
        key_file = os.path.join(RSA_ROOT_DIR, 'root-ca.key')
        crl_out = os.path.join(RSA_ROOT_DIR, 'crl', 'root-ca.crl')
        cert_pem = os.path.join(RSA_ROOT_DIR, 'root-ca.pem')
    try:
        subprocess.run([
            'openssl', 'ca', '-revoke', cert_file,
            '-config', config,
            '-passin', f'pass:{passwd}'
        ], check=True, capture_output=True)
        subprocess.run([
            'openssl', 'ca', '-gencrl',
            '-keyfile', key_file,
            '-cert', cert_pem,
            '-out', crl_out,
            '-config', config,
            '-passin', f'pass:{passwd}'
        ], check=True, capture_output=True)
        shutil.copy(
            os.path.join(RSA_INTERMEDIATE_DIR, 'crl', 'intermediate-ca.crl'),
            os.path.join(RSA_SERVER_DIR, 'crl', 'intermediate-ca.crl')
        )
        users = load_users()
        for user in users.values():
            for cert in user.get('certs', []):
                if cert['serial'].upper().lstrip('0') == serial.upper().lstrip('0'):
                    cert['status'] = 'revoked'
        save_users(users)
        return jsonify({'success': True, 'message': '证书已成功吊销，CRL 已更新'})
    except subprocess.CalledProcessError:
        return jsonify({'success': False, 'message': '吊销失败，请检查口令是否正确'})

@app.route('/revoke_sm2', methods=['POST'])
def revoke_sm2():
    if not session.get('logged_in'):
        return jsonify({'success': False, 'message': '未登录'})
    cert_name = request.form.get('cert_name')
    passwd = request.form.get('password', '')
    users = load_users()
    cert_file = os.path.join(SM2_USER_CERTS_DIR, cert_name + '.pem')
    if not os.path.exists(cert_file):
        return jsonify({'success': False, 'message': '找不到证书文件'})
    revoked_der = os.path.join(SM2_INTERMEDIATE_DIR, 'crl', 'revoked_certs.der')
    temp_der = os.path.join(SM2_INTERMEDIATE_DIR, 'crl', 'temp_revoked.der')
    crl_out = os.path.join(SM2_INTERMEDIATE_DIR, 'crl', 'sm2-intermediate-ca.crl')
    try:
        subprocess.run(
            [GMSSL, 'certrevoke',
             '-in', cert_file,
             '-reason', 'keyCompromise',
             '-out', temp_der],
            check=True, capture_output=True
        )
        with open(revoked_der, 'ab') as f:
            with open(temp_der, 'rb') as t:
                f.write(t.read())
        subprocess.run(
            [GMSSL, 'crlgen',
             '-in', revoked_der,
             '-cacert', os.path.join(SM2_INTERMEDIATE_DIR, 'intermediate-ca.pem'),
             '-key', os.path.join(SM2_INTERMEDIATE_DIR, 'intermediate-ca.key'),
             '-pass', passwd,
             '-gen_authority_key_id',
             '-crl_num', '1',
             '-out', crl_out],
            check=True, capture_output=True
        )
        shutil.copy(crl_out, os.path.join(RSA_SERVER_DIR, 'crl', 'sm2-intermediate-ca.crl'))
        for user in users.values():
            for cert in user.get('certs', []):
                if cert.get('cert_name') == cert_name:
                    cert['status'] = 'revoked'
        save_users(users)
        return jsonify({'success': True, 'message': 'SM2 证书已吊销，CRL 已更新'})
    except subprocess.CalledProcessError:
        return jsonify({'success': False, 'message': 'SM2 吊销失败，请检查口令'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
