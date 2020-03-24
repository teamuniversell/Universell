import smtplib 
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 
   
def send_attachment(fromaddr, toaddr, password, filepath):
    
  
    msg = MIMEMultipart() 
    
    
    msg['From'] = fromaddr 
    
   
    msg['To'] = toaddr 
  
    
    msg['Subject'] = "Malware Script"
    
    
    body = "Convert this into executable and attack your target"
    
     
    msg.attach(MIMEText(body, 'plain')) 
    
    
    filename = filepath
    attachment = open(filename, "rb") 
    
    
    p = MIMEBase('application', 'octet-stream') 
    
    
    p.set_payload((attachment).read()) 
    
    
    encoders.encode_base64(p) 
    
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename) 
    
   
    msg.attach(p) 
    
    
    s = smtplib.SMTP('smtp.gmail.com', 587) 
    
    
    s.starttls() 
    
    
    s.login(fromaddr, password) 
    
    text = msg.as_string() 
    
    
    s.sendmail(fromaddr, toaddr, text) 
    
    
    s.quit() 


