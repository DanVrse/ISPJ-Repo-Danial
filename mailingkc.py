import smtplib
from email.mime.base import MIMEBase
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import  formatdate
from email import encoders

def send_mail(send_from, send_to, subject, filename):
    # assert isinstance(send_to, list)


    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = send_to#", ".join()
    msg['Subject'] = subject

    msgText = MIMEText('<b>%s</b>' % ("Thank you for creating an account with us. This is the Key and Certificate we use to secure your information. Certificate needs to be presented to login"), 'html')
    msg.attach(msgText)
    zip = MIMEBase('application', 'zip')
    with open(f"./tempfiles/{filename}.zip", "rb") as zf:
        zip.set_payload(zf.read())
    encoders.encode_base64(zip)
    zip.add_header('Content-Disposition', 'attachment',
                   filename=filename + '.zip')
    msg.attach(zip)

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as smtpObj:
            smtpObj.ehlo()
            smtpObj.starttls()
            smtpObj.login("shakeshackproject@gmail.com", "Shakeshackproject123")
            smtpObj.sendmail(send_from, send_to, msg.as_string())
            smtpObj.quit()
    except Exception as e:
        print(e)
    # smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    # smtpObj.ehlo()
    # smtpObj.starttls()
    # smtpObj.login("shake@email.com", "Shakeshackproject123")

