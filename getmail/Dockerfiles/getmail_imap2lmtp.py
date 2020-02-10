import ssl
import time
import os
import datetime
import email
import smtplib
import threading
import traceback
import re
import base64
import quopri
import signal
import logging
import sys
import socket

import imapclient
import configparser

class Getmail(threading.Thread):
   
    def __init__(self, settings):
        threading.Thread.__init__(self)
        self.event = threading.Event()
        self.settings = settings
        self.setName("Thread-%s" % self.settings["config_name"])
        self.imap = None
        self.exit_imap_idle_loop = False
        self.exception_counter = 0
        self.print_lock = threading.Lock()
        self.last_renew_imap_idle_connection = time.monotonic()
        self.idle_check_timeout = 1

    def run(self):
        while not self.exit_imap_idle_loop:
          try: 
            self.event.wait(5)
            self.imap_idle()
          except Exception as e:
            logging.error("ERROR: %s" % (e))
            #traceback.print_exc()
          
          if not self.exit_imap_idle_loop:        
            self.exception_counter += 1
            logging.error("ERROR: restart thread in %s minutes (counter: %d)" % (self.exception_counter * self.exception_counter, self.exception_counter))
            self.event.wait(60 * self.exception_counter * self.exception_counter )
 
    def imap_idle_stop(self):
        logging.info("IMAP_IDLE_STOP")
        self.exit_imap_idle_loop = True
        self.event.set()

 
    def imap_start_connection(self):
        logging.info("Start Getmail - server: %s:%s, username: %s" % (self.settings["imap_hostname"], self.settings["imap_port"], self.settings["imap_username"]))

        self.imap = imapclient.IMAPClient(self.settings["imap_hostname"],port=self.settings["imap_port"], ssl=True, use_uid=True)
        login_status = self.imap.login(self.settings["imap_username"],self.settings["imap_password"])
        #logging.info("Login - status: %s" % login_status)

        if not self.imap.has_capability('IDLE'):
            logging.error("Server doesn't support IDLE!!")
            sys.exit()
        
#        if self.settings["imap_debug"]:
#          self.imap.debug = True
#          logging.basicConfig(level=logging.DEBUG)
#        else:
#          self.imap.debug = False
#          logging.basicConfig(level=logging.INFO)

        self.imap.select_folder('INBOX')

        self.exception_counter = 0

        self.create_imap_move_folder()

    def imap_close_connection(self):
        if self.imap != None:
          status_logout = self.imap.logout()
          #logging.info("Close IMAP connection - status_logout: %s" % (status_logout))

    def imap_idle(self):
        self.imap_start_connection()
        self.imap_fetch_mail()

        # Start IDLE mode
        self.imap.idle()

        logging.info("Join infinite loop and wait for new mails, cancel with Ctrl-c")
        while not self.exit_imap_idle_loop:

            # Wait for up to x seconds for an IDLE response
            # https://imapclient.readthedocs.io/en/2.1.0/advanced.html
            start_time_idle_check = time.monotonic()
            responses = self.imap.idle_check(timeout=self.idle_check_timeout)
            execution_time_idle_check = time.monotonic() - start_time_idle_check

            self.check_imap_idle_response(responses, execution_time_idle_check)

        # End IDLE mode
        self.imap.idle_done()
        self.imap_close_connection()

    def check_imap_idle_response(self, responses, execution_time_idle_check):
        #https://tools.ietf.org/html/rfc3501#page-71

        self.renew_imap_idle_connection()

        if responses == []:
            if (execution_time_idle_check < self.idle_check_timeout / 2):
              logging.info("TEST -- IMAP IDLE response: %s " % responses)
              raise Exception('idle_check responded too quickly, something is wrong with the IMAP Idle connection (execution_time_idle_check: %s' % execution_time_idle_check)
            else:
              # default action, when everything is ok  
              return  
        elif responses == None:
            return 
        elif responses == [(b'OK', b'Still here')]:
            return 
        elif responses == [(b'BYE', b'timeout')]:
            raise Exception('IMAP Connection Timeout, restart connection') 

        logging.debug("IMAP IDLE response: %s " % responses)
        for item in responses:
            if len(item) == 2:
              if item[1] == b'EXISTS':
                self.imap.idle_done()
                self.imap_fetch_mail() 
                self.imap.idle()


    def renew_imap_idle_connection(self):
        # https://tools.ietf.org/html/rfc2177
        # Because of that, clients using IDLE are advised to terminate the IDLE and
        # re-issue it at least every 29 minutes to avoid being logged off.
        fifteen_minutes = 15*60

        if time.monotonic() - self.last_renew_imap_idle_connection > fifteen_minutes:
            self.last_renew_imap_idle_connection = time.monotonic()
            logging.debug("renew imap idle session")
            self.imap.idle_done()
            self.imap.idle()
            self.check_imap_idle_response_counter_between_renew = 0

    def imap_fetch_mail(self):
        #https://github.com/mjs/imapclient/blob/011748fd687c43636a8ef2c3acb9fa85782b91bc/examples/email_parsing.py
        messages = self.imap.search(criteria=u'ALL')
        for uid, message_data in self.imap.fetch(messages, 'RFC822').items():
          email_message = email.message_from_bytes(message_data[b'RFC822'])
          #logging.info("%s,%s,%s" % (uid, email_message.get('From'), email_message.get('Subject')) )
          if self.lmtp_deliver_mail(email_message):
            if self.settings["imap_move_enable"]:
              self.imap_move_mail(uid)
            else:
              self.imap_delete_mail(uid)
              
                
    def imap_delete_mail(self, uid):
        self.imap.delete_messages([uid])
        self.imap.expunge()
        logging.info('IMAP delete: delete email (uid: %s)' % str(uid) )

    def create_imap_move_folder(self):
        if self.settings["imap_move_enable"]:
          if self.imap.folder_exists(self.settings["imap_move_folder"]):
            logging.info("imap_move_folder (%s) already exists, nothing to do." % (self.settings["imap_move_folder"]))
          else:
            status =  self.imap.create_folder(self.settings["imap_move_folder"])
            logging.info("imap_move_folder (%s) create status: %s " % (self.settings["imap_move_folder"], status))


    def imap_move_mail(self, uid):
        self.imap.move(uid, self.settings["imap_move_folder"])
        logging.info('IMAP move: move email to imap_move_folder (%s)' % (self.settings["imap_move_folder"]) )

 
    def lmtp_deliver_mail(self, email_message):
       logging.info( "LMTP deliver: start -- LMTP host: %s:%s" % (self.settings["lmtp_hostname"], self.settings["lmtp_port"]))
       try: 
         
         try:
           lmtp = smtplib.LMTP(self.settings["lmtp_hostname"], self.settings["lmtp_port"])
         except ConnectionRefusedError as e:
           logging.error("LMTP deliver (ConnectionRefusedError): %s" % (e))
           return False
         except socket.gaierror as e:
           logging.error("LMTP deliver (LMTP-Server is not reachable): %s" % (e))  
           return False  

         if self.settings["lmtp_debug"]:
                lmtp.set_debuglevel(1)

         email_message['X-getmail-retrieved-from-mailbox-user'] = self.settings["imap_username"]

         try:
           #https://docs.python.org/3/library/smtplib.html#smtplib.SMTP.send_message
           logging.info(email.header.make_header(email.header.decode_header(email_message.get('From'))))
           lmtp.send_message(email_message, to_addrs=self.settings["lmtp_recipient"])
         except Exception as e:
           logging.error("LMTP deliver (Exception - send_message #1): %s" % (e))
           traceback.print_exc()

           try:
             email_from = email_message.get('From')
             lmtp.send_message(email_message, from_addr=email_from, to_addrs=self.settings["lmtp_recipient"])
           except Exception as e:
             logging.error("LMTP deliver (Exception - send_message #2): %s" % (e))
             return False
                 
           #return False
         finally:
           lmtp.quit()

         try:
           email_from_decoded    = email.header.make_header(email.header.decode_header(email_message.get('From')))
           email_subject_decoded = email.header.make_header(email.header.decode_header(email_message.get('Subject')))
           logging.info(u'LMTP deliver: new eMail from: [%s], subject: [%s] ----> LMTP recipient: %s' % (email_from_decoded, email_subject_decoded, self.settings["lmtp_recipient"]) )
         except Exception as e:
           logging.error("LMTP deliver (Exception - decode error): %s" % (e))
           logging.info(u'LMTP deliver: new eMail ----> LMTP recipient: %s' % (self.settings["lmtp_recipient"]) )
            
         return True

       except Exception as e:
         logging.error("LMTP deliver (Exception): %s" % (e))
         logging.error(traceback.format_exc())
         return False


########################################################################################################################
########################################################################################################################
########################################################################################################################


def start_getmail():

  all_config_sections = get_config_sections()
  all_connections = {}

  for config_name in all_config_sections:
        all_connections[config_name] = Getmail(all_config_sections[config_name])
        all_connections[config_name].start()  

  try: 
    exit_program = False
    while not exit_program:
      try:
        signal.pause()
      except KeyboardInterrupt:
        exit_program = True
      except Exception as e:
        logging.error("ERROR: %s" % (e))
        traceback.print_exc()
  finally:
    logging.info("START: shutdown all IMAP connections")
    for config_name in all_connections:
      all_connections[config_name].imap_idle_stop()
    for config_name in all_connections:
      all_connections[config_name].join()
    logging.info("END: shutdown all IMAP connections")


def get_config_sections():

  if os.path.isfile("./settings.ini"):
    config_file_path = "./settings.ini"
  else:
    logging.error("ERROR settings.ini not found!")
    return

  logging.info("use config file: %s" % config_file_path)
  configparser_file = configparser.ConfigParser()
  configparser_file.read([os.path.abspath(config_file_path)])

  all_config_sections = {}


  for config_name in configparser_file.sections():

        all_config_sections[config_name] = {}
        all_config_sections[config_name]["config_name"]      = config_name
        all_config_sections[config_name]["imap_hostname"]    = configparser_file.get(config_name, 'imap_hostname')
        all_config_sections[config_name]["imap_port"]        = int (configparser_file.get(config_name, 'imap_port') )
        all_config_sections[config_name]["imap_username"]    = configparser_file.get(config_name, 'imap_username')
        all_config_sections[config_name]["imap_password"]    = configparser_file.get(config_name, 'imap_password')
        all_config_sections[config_name]["imap_move_folder"] = configparser_file.get(config_name, 'imap_move_folder')
        if configparser_file.get(config_name, 'imap_move_enable') == "False":
                all_config_sections[config_name]["imap_move_enable"] = False
        else:
                all_config_sections[config_name]["imap_move_enable"] = True

        if configparser_file.get(config_name, 'imap_debug') == "True":
                all_config_sections[config_name]["imap_debug"] = True
        else:
                all_config_sections[config_name]["imap_debug"] = False

        all_config_sections[config_name]["lmtp_hostname"]    = configparser_file.get(config_name, 'lmtp_hostname')
        all_config_sections[config_name]["lmtp_port"]        = int (configparser_file.get(config_name, 'lmtp_port') )
        all_config_sections[config_name]["lmtp_recipient"]   = configparser_file.get(config_name, 'lmtp_recipient')
        if configparser_file.get(config_name, 'lmtp_debug') == "True":
                all_config_sections[config_name]["lmtp_debug"] = True
        else:
                all_config_sections[config_name]["lmtp_debug"] = False


  return all_config_sections


def exit_gracefully(signum, frame):
    logging.info("Caught signal %d" % signum)
    raise KeyboardInterrupt
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT,  exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    logging.basicConfig(
      format='%(asctime)s - %(threadName)s - %(levelname)s: %(message)s',
      level=logging.INFO
    )

    start_getmail()
