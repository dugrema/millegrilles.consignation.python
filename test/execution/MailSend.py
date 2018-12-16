import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg.set_content("Bonjour Mathieu, c'est dev2")

msg['Subject'] = 'Bonjour de dev2'
msg['From'] = 'dev2.millegrilles@mdugre.info'
msg['To'] = 'mathieu.dugre@me.com'

s = smtplib.SMTP_SSL('mail.mdugre.info', 465)
s.login('dev2.millegrilles@mdugre.info', 'PASSWORD')
s.send_message(msg)
s.quit()
