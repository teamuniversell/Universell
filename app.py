from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, jsonify
from wtforms import Form, StringField, PasswordField, validators, ValidationError 
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from hack import change_mac, current_mac, scan, ArpSpoofTask, PacketSniffer, DnsSpoof, Interceptor, brute_force_attack
from code_injector import Injector
from malware import *
from threading import Thread
from crawler import *
import time
from scanner import *


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/universell'

db = SQLAlchemy(app)

arp_spoof_attack = ArpSpoofTask()
packet_sniffer = PacketSniffer()
dns_spoof_attack = DnsSpoof()
interceptor = Interceptor()
injector = Injector()
crawler = None
scanner = None

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=False)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class RegisterForm(Form):
    name = StringField('Name', validators=[validators.DataRequired(), validators.Length(min=4,                                  
    max=30)])
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    password_confirm = PasswordField('Confirm password', validators=[validators.DataRequired(), validators.EqualTo('password', message="Passwords don't match")])

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email Already Taken')


class MainScreen(Form):
    target_url= StringField('Target URL', validators=[validators.DataRequired()])



class MacChanger(Form):
    interface = StringField('Inteface Name', validators=[validators.DataRequired()]) 
    mac = StringField('MAC', validators=[validators.DataRequired(),  validators.Regexp('\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', message="Invalid MAC")])
        


class LoginForm(Form):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])


class NetworkScanForm(Form):
    ip = StringField('IP Or IP Range', validators=[validators.DataRequired()])


class ArpSpoofingForm(Form):
    target_ip = StringField('Target IP', validators=[validators.DataRequired(),  validators.Regexp('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', message="Invalid IP Format")])
    spoof_ip = StringField('Spoof IP', validators=[validators.DataRequired(),  validators.Regexp('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', message="Invalid IP Format")])
    

class PacketSniffingForm(Form):
    interface = StringField('Interface',  validators=[validators.DataRequired()])


class DnsSpoofingForm(Form):
    target_url= StringField('Target URL', validators=[validators.DataRequired()])
    spoof_ip = StringField('Spoof IP', validators=[validators.DataRequired(),  validators.Regexp('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', message="Invalid IP Format")])


class FileInterceptorForm(Form):
    evil_link = StringField('Evil File Link', validators=[validators.DataRequired()])


class CodeInjectorForm(Form):
    code = StringField('Code To Inject', validators=[validators.DataRequired()])


class MalwareForm(Form):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired()])
    download_link = StringField('Download Link', validators=[validators.DataRequired()])


class CrawlerForm(Form):
    url = StringField('URL', validators=[validators.DataRequired()])


class DictionaryForm(Form):
    url = StringField('Target URL', validators=[validators.DataRequired()])
    username_field = StringField('Username Field Name', validators=[validators.DataRequired()])
    pass_field = StringField('Password Field Name', validators=[validators.DataRequired()])
    username_guess = StringField('Username Guess', validators=[validators.DataRequired()])
    submit_field = StringField('Submit Field Name', validators=[validators.DataRequired()])


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/blog")
def blog():
    return render_template("blog.html")



@app.route("/main", methods=['GET', 'POST'])
def main():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        global scanner
        form = MainScreen(request.form)
        def scan_vuln():
            scanner = 'abc'
            work(form.target_url.data)
        if request.method == "POST" and form.validate():
            t = Thread(target = scan_vuln)
            t.start()
            flash("Scanning...", 'success')
            return render_template("main_screen.html", form = form, results = ['Check console for results'])
        return render_template("main_screen.html", form = form)

    


@app.route("/mac", methods=['GET', 'POST'])
def mac():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = MacChanger(request.form)
        if request.method == "POST" and form.validate():
            results = change_mac(form.interface.data, form.mac.data)
            if(results):
                msg = "MAC Address Changed Successfully"
                return render_template("mac_changer.html", form=form, msg = msg, results = results) 
            else:
                error = "Operation Was Not Successful"
                return render_template("mac_changer.html", form=form, error = error)
            return redirect(url_for("mac"))
        return render_template("mac_changer.html", form=form)
    


@app.route("/network", methods=['GET', 'POST'])
def network():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = NetworkScanForm(request.form)
        if request.method == "POST" and form.validate():
            results = scan(form.ip.data)
            if(results):
                msg = "Scanned Successfully"
                return render_template("network_scanning.html", form=form, msg=msg, results=results)
            else:
                error = "No Results Found"
                return render_template("network_scanning.html", form=form, error= error)

        return render_template("network_scanning.html", form=form)



@app.route("/arp", methods=['GET', 'POST'])
def arp_spoof():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = ArpSpoofingForm(request.form)
        if request.method == "POST" and form.validate():
            if 'restore' in request.form:
                msg = "Restore Was Successful"
                results = arp_spoof_attack.restore(form.target_ip.data, form.spoof_ip.data)
            else:
                msg = "ARP Spoofing Was Successful"
                results = arp_spoof_attack.launch_arp_spoof(form.target_ip.data, form.spoof_ip.data)
                
            if(results):
                arp_spoof_attack.continue_arp_spoof(form.target_ip.data, form.spoof_ip.data)
                return render_template("arp_spoof.html", form=form, msg = msg, results = results) 
            else:
                error = "Operation Was Not Successful"
                return render_template("arp_spoof.html", form=form, error = error)
            return 'SUccess'
        return render_template("arp_spoof.html", form=form)


@app.route("/sniff", methods=['GET', 'POST'])
def packet_sniff():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = PacketSniffingForm(request.form)
        if request.method == "POST" and form.validate():
            if packet_sniffer.continue_packet_sniff(form.interface.data) == "running":
                flash("Sniffer Already Running...", "danger")
            else:
                flash("Packet Sniffing Started Successfully", "success")

            return redirect(url_for("packet_sniff"))
            
        return render_template("packet_sniffing.html", form=form)


@app.route('/sniff_array', methods=['GET', 'POST'])
def sniff_array():
    results = packet_sniffer.results
    return jsonify(results=results)


@app.route('/crawl', methods=['GET', 'POST'])
def crawl():
    global crawler
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = CrawlerForm(request.form)
        if request.method == "POST" and form.validate():
            seedurl = form.url.data
            crawler = Crawler(seedurl)

            def crawl_sites():
                for url in crawler.crawled_urls:
                    crawler.user_output.append(">>>" +url)
                    print('>>>', url)

            t = Thread(target = crawl_sites)
            t.start()

            results = 'Crawling...'

            flash("Crawler Started Successfully", "success")
            
        return render_template("crawler.html", form=form)



@app.route('/crawl_array', methods=['GET', 'POST'])
def crawl_array():
    if crawler:
        results = crawler.user_output
        return jsonify(results=results)
    else:
        return ''
    
@app.route('/scan_array', methods=['GET', 'POST'])
def scan_array():
    if scanner:
        results = scanner.scan_results
        return jsonify(results=results)
    else:
        'Not initialized'
        return ''
    


@app.route('/clear', methods=['GET', 'POST'])
def clear_sniffed_results():
    packet_sniffer.results.clear()
    if len(packet_sniffer.results) == 0:
        return 'cleared'
    return ''



@app.route('/restore_url', methods=['POST'])
def restore_url():
    dns_spoof_attack.restore()
    flash('URL Restored', 'success')
    return ''
    

@app.route('/drop_connection', methods=['POST'])
def drop_connection():
    dns_spoof_attack.drop_connection()
    flash('Remote Connection Dropped Successfully', 'success')
    return ''


@app.route('/restore_connection', methods=['POST'])
def restore_connection():
    dns_spoof_attack.establish_connection()
    flash('Remote Connection Restored Successfully', 'success')
    return ''  


@app.route('/dns', methods=['GET', 'POST'])
def dns_spoof():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = DnsSpoofingForm(request.form)
        if request.method == "POST" and form.validate():
           
            try:
                if not dns_spoof_attack.url:
                    dns_spoof_attack.set_forward_chain()
                    dns_spoof_attack.set_params(form.target_url.data, form.spoof_ip.data)
                    dns_spoof_attack.bind()
                    results = "Spoofing DNS response to: " + form.spoof_ip.data
                else:
                    dns_spoof_attack.set_params(form.target_url.data, form.spoof_ip.data)
                    results = "Spoofing DNS response to: " + form.spoof_ip.data
                
                flash('DNS Spoofing Was Successful', 'success')
            except Exception as e:
                print(e)
                results = ""
                flash('Operation Was Not Successful', 'danger')

            return render_template("dns_spoof.html", form=form, results = [results])

           
        return render_template("dns_spoof.html", form=form)



@app.route("/file", methods=['GET', 'POST'])
def file_interceptor():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = FileInterceptorForm(request.form)
        if request.method == "POST" and form.validate():
            interceptor.set_file(form.evil_link.data)
            interceptor.enable_forward_chain()
            interceptor.bind()
            results = [
                'Interceptor started successfully...',
                'All files will be redirected to: ',
                form.evil_link.data 
            ]
            flash('File Interception Was Successful', 'success')

            return render_template("file_interceptor.html", form=form, results=results)

           
        return render_template("file_interceptor.html", form=form)


@app.route("/code", methods=['GET', 'POST'])
def code_injector():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = CodeInjectorForm(request.form)
        if request.method == "POST" and form.validate():
            if 'remove' in request.form:
                results = ''
                injector.remove_injection()
                flash('Injector Removed Successfully', 'success')
            else:
                results = ''
                if not injector.injector_running:
                    injector.enable_forward_chain()
                    injector.set_injection(form.code.data)
                    injector.bind()
                    results = [
                        'Injector started successfully...'
                    ]
                    flash('Code Injection Was Successful', 'success')
                else:
                    results = [
                        'Injector modified successfully...'
                    ]
                    injector.set_injection(form.code.data)
                    flash('Code Modification Was Successful', 'success')
            
            return render_template("code_injector.html", form=form, results=results)

           
        return render_template("code_injector.html", form=form)




@app.route("/malware", methods=['GET', 'POST'])
def malware():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = MalwareForm(request.form)
        results = ''
        if request.method == "POST" and form.validate():

            malware = Malware(form.email.data, form.password.data, form.download_link.data)
            malware.create()

            results = [
                'Malware code created successfully...',
                'LaZagne download link:--->' + form.download_link.data,
                'If you don\'t receive an email, please retry in two minutes'
            ]
            flash('Malware Created Successfully', 'success')
            
        return render_template("malware.html", form=form, results=results)



@app.route("/steal", methods=['GET', 'POST'])
def password_stealer():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = MalwareForm(request.form)
        results = ''
        if request.method == "POST" and form.validate():

            malware = Malware(form.email.data, form.password.data)
            malware.create_stealer()

            results = [
                'Password Stealer created successfully...',
                'If you don\'t receive an email, please retry in two minutes'
            ]
            flash('Password Stealer Created Successfully', 'success')
            
        return render_template("password_stealer.html", form=form, results=results)

        


    
@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        form = MainScreen(request.form)
        return render_template("main_screen.html", form = form)
    else:
        form = LoginForm(request.form)
        if request.method == "POST" and form.validate():
            user = Users.query.filter_by(email=form.email.data).first()
            if user:
                if check_password_hash(user.password,form.password.data):
                    session['logged_in'] = True
                    session['logged_email'] = form.email.data
                    return redirect(url_for("main"))

                else:
                    flash('Invalid Email Or Password', 'danger')
                    return redirect(url_for('login'))

            else:
                flash('Invalid Email Or Password', 'danger')
                return redirect(url_for('login'))
                
        
        return render_template("login.html", form=form)
       
    
@app.route("/dict", methods=['GET', 'POST'])
def dictionary_attack():
    if not session.get('logged_in'):
        flash("Unauthorized Access", "danger")
        return redirect(url_for("login"))
    else:
        form = DictionaryForm(request.form)
        if request.method == "POST" and form.validate():
            results = brute_force_attack(form.url.data, form.username_field.data, form.pass_field.data, form.username_guess.data, form.submit_field.data)
            if(results):
                msg = "Attacked Successfully"
                results = "Success..\n Password--->" + results

                return render_template("dictionary_attack.html", form=form, msg=msg, results=[results])
            else:
                error = "Attack Was Not Successful"
                return render_template("dictionary_attack.html", form=form, error= error)

        return render_template("dictionary_attack.html", form=form)



@app.route("/register", methods=['GET', 'POST'])
def register():
    if session.get('logged_in'):
        form = MainScreen(request.form)
        return render_template("main_screen.html", form = form)
    else:
        form = RegisterForm(request.form)
        if request.method == "POST" and form.validate():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = Users(name=form.name.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('You are registered successfully and can log in', 'success')
            return redirect(url_for("login"))
        return render_template("signup.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))



app.secret_key = "secret123"
app.run(debug=True)