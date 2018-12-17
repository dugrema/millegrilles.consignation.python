import smtplib
from email.message import EmailMessage
from millegrilles.dao.Configuration import TransactionConfiguration

configuration = TransactionConfiguration()
configuration.loadEnvironment()

# print(str(configuration._email_config))

msg = EmailMessage()
msg.set_content("Bonjour Mathieu, c'est dev2")

msg['Subject'] = 'Bonjour de dev2'
msg['From'] = configuration.email_from
msg['To'] = configuration.email_to

# s = smtplib.SMTP_SSL('mail.mdugre.info', 465)
# s.login('dev2.millegrilles@mdugre.info', 'PASSWORD')

s = smtplib.SMTP_SSL(configuration.email_host, configuration.email_port)
s.login(configuration.email_user, configuration.email_password)

s.send_message(msg)
s.quit()
