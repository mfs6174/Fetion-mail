/***************************************************************************
 *   Copyright (C) 2012 by mfs6174                                         *
 *   mfs6174@gmail.com                                                     *
 *   Copyright (C) 2010 by lwp                                             *
 *   levin108@gmail.com                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/
 
#include <openfetion.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;
#define BUFLEN 1024
const int waittime=25;

int   password_inputed = 0;
int   mobileno_inputed = 0;
int   tono_inputed = 0;
int   message_inputed = 0;
User *user;
pthread_t th;
int sigrelog=0;
int failcount=0;
string ads("fake@false.fake");
 
static void usage(char *argv[]);
 
int fx_login(const char *mobileno, const char *password)
{
  Config           *config;
  FetionConnection *tcp;
  FetionSip        *sip;
  char             *res;
  char             *nonce;
  char             *key;
  char             *aeskey;
  char             *response;
  int               local_group_count;
  int               local_buddy_count;
  int               group_count;
  int               buddy_count;
  int               ret;
 
  /* construct a user object */
  user = fetion_user_new(mobileno, password);
  /* construct a config object */
  config = fetion_config_new();
  /* attach config to user */
  fetion_user_set_config(user, config);
 
  /* start ssi authencation,result string needs to be freed after use */
  res = ssi_auth_action(user);
  /* parse the ssi authencation result,if success,user's sipuri and userid
   * are stored in user object,orelse user->loginStatus was marked failed */
  parse_ssi_auth_response(res, user);
  free(res);
 
  /* whether needs to input a confirm code,or login failed
   * for other reason like password error */
  if(USER_AUTH_NEED_CONFIRM(user) || USER_AUTH_ERROR(user)) {
    debug_error("authencation failed");
    return 1;
  }
 
  /* initialize configuration for current user */
  if(fetion_user_init_config(user) == -1) {
    debug_error("initialize configuration");
    return 1;
  }
 
  if(fetion_config_download_configuration(user) == -1) {
    debug_error("download configuration");
    return 1;
  }
 
  /* set user's login state to be hidden */
  fetion_user_set_st(user, P_ONLINE);
 
  /* load user information and contact list information from local host */
  fetion_user_load(user);
  fetion_contact_load(user, &local_group_count, &local_buddy_count);
 
  /* construct a tcp object and connect to the sipc proxy server */
  tcp = tcp_connection_new();
  if((ret = tcp_connection_connect(tcp, config->sipcProxyIP, config->sipcProxyPort)) == -1) {
    debug_error("connect sipc server %s:%d\n", config->sipcProxyIP, config->sipcProxyPort);
    return 1;
  }
 
  /* construct a sip object with the tcp object and attach it to user object */
  sip = fetion_sip_new(tcp, user->sId);
  fetion_user_set_sip(user, sip);
 
  /* register to sipc server */
  if(!(res = sipc_reg_action(user))) {
    debug_error("register to sipc server");
    return 1;
  }
 
  parse_sipc_reg_response(res, &nonce, &key);
  free(res);
  aeskey = generate_aes_key();
 
  response = generate_response(nonce, user->userId, user->password, key, aeskey);
  free(nonce);
  free(key);
  free(aeskey);
 
  /* sipc authencation,you can printf res to see what you received */
  if(!(res = sipc_aut_action(user, response))) {
    debug_error("sipc authencation");
    return 1;
  }
 
  if(parse_sipc_auth_response(res, user, &group_count, &buddy_count) == -1) {
    debug_error("authencation failed");
    return 1;
  }
 
  free(res);
  free(response);
 
  if(USER_AUTH_ERROR(user) || USER_AUTH_NEED_CONFIRM(user)) {
    debug_error("login failed");
    return 1;
  }
 
  /* save the user information and contact list information back to the local database */
  fetion_user_save(user);
  fetion_contact_save(user);
 
  //\* these... fuck the fetion protocol *\/ */
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  char buf[1024];
  if(setsockopt(user->sip->tcp->socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
  	debug_error("settimeout");
  	return 1;
  }
  tcp_connection_recv(user->sip->tcp, buf, sizeof(buf));
  StateType sttt=P_ONLINE;
  if (fetion_user_set_state(user,sttt)==-1)
  {
    debug_error("set-state-fail");
    return 1;
  } 
  return 0;
}
 
int send_message(const char *mobileno, const char *receiveno, const char *message)
{
  Conversation *conv;
  Contact      *contact;
  Contact      *contact_cur;
  Contact      *target_contact = NULL;
  int           daycount;
  int           monthcount;
 
  /* send this message to yourself */
  if(*receiveno == '\0' || strcmp(receiveno, mobileno) == 0) {
    /* construct a conversation object with the sipuri to set NULL
     * to send a message to yourself  */
    conv = fetion_conversation_new(user, NULL, NULL);
    if(fetion_conversation_send_sms_to_myself_with_reply(conv, message) == -1) {
      debug_error("send message \"%s\" to %s", message, user->mobileno);
      return 1;
    }
  }else{
    /* get the contact detail information by mobile number,
     * note that the result doesn't contain sipuri */
    contact = fetion_contact_get_contact_info_by_no(user, receiveno, MOBILE_NO);
    if(!contact) {
      debug_error("get contact information of %s", receiveno);
      return 1;
    }
 
    /* find the sipuri of the target user */
    foreach_contactlist(user->contactList, contact_cur) {
      if(strcmp(contact_cur->userId, contact->userId) == 0) {
        target_contact = contact_cur;
        break;
      }
    }
 
    if(!target_contact) {
      debug_error("sorry,maybe %s isn't in your contact list");
      return 1;
    }
 
    /* do what the function name says */
    conv = fetion_conversation_new(user, target_contact->sipuri, NULL);
    //	if(fetion_conversation_send_sms_to_phone_with_reply(conv, message, &daycount, &monthcount) == -1) {
    if(fetion_conversation_send_sms_with_reply(conv,message) == -1) {
      debug_error("send sms to %s", receiveno);
      return 1;
    }else{
      debug_info("successfully send sms to %s\nyou have sent %d messages today, %d messages this monthcount",
                 receiveno, daycount, monthcount);
      return 0;
    }
  }
  return 0;
}

int mysendmail(const char mailto[],const char subj[],const char cont[])
{
  static string mailfrom="fetion@mfs6174.org";
  FILE *fp=popen("/usr/lib/sendmail -t > /dev/null","w");
  if (fp==NULL)
    return -1;
  fprintf(fp,"To: %s\n",mailto);
  fprintf(fp,"From: %s\n",mailfrom.c_str());
  fprintf(fp, "Content-type: %s\n", "text/html;charset=utf-8");
  fprintf(fp,"Subject: %s\n",subj);
  fprintf(fp,"%s\n",cont);
  pclose(fp);
  return 0;
}

void recvMsg(User *user){
  FetionSip *sip = user->sip;
  int type;
  SipMsg *msg, *pos;
  fd_set fd_read;
  int ret,err;
  Message *sipmsg;
  for(;;)
  {
    if (sigrelog)
      break;
    FD_ZERO(&fd_read);
    FD_SET(sip->tcp->socketfd, &fd_read);
    ret = select (sip->tcp->socketfd+1, &fd_read, NULL, NULL, NULL);
    if (ret == -1 || ret == 0)
    {
      err=1;
      debug_info ("Error.. to read socket");
    }
    if (!FD_ISSET (sip->tcp->socketfd, &fd_read))
    {
      sleep (100);
      continue;
    }
    msg = fetion_sip_listen(sip,&err);
    if (err)
    {
      failcount++;
      if (failcount>5)
      {
        sigrelog=1;
        break;
      }
    }
    pos = msg;
    while(pos != NULL){
      type = fetion_sip_get_type(pos->message);
      switch(type)
      {
      case SIP_NOTIFICATION :
        //nothing
        break;
      case SIP_MESSAGE:
        //nothing
        sipmsg = NULL;
        fetion_sip_parse_message(sip, pos->message, &sipmsg);
        break;
      case SIP_INVITATION:
        //nothing
        break;
      case SIP_INCOMING :
        //nothing
        break;
      case SIP_SIPC_4_0:
        //nothing
        break;
      default:
        //nothing
        break;
      }
      //int position = strspn(pos->message, "M");
      char * pntsip=strstr(pos->message,"sip:"),* pntdm=strstr(pos->message,"D:");
      if(pntsip!=NULL&&pntdm!=NULL)//position == 1)
      {
        string pmsg(pos->message),subj("新的飞信消息"),ctt(" ");
        int tp=pmsg.find("D:"),tph=pmsg.find("GMT");
        if (tp!=string::npos && tph!=string::npos)
          subj=subj+pmsg.substr(tp,tph-tp+3);
        tp=pmsg.find("XI:");
        int kp=-1;
        if (tp!=string::npos)
          kp=tp+36;
        else
          if (tph!=string::npos)
            kp=tph+4;
        if (kp>0)
          ctt=pmsg.substr(kp);
        else
          ctt=pmsg;
        mysendmail(ads.c_str(),subj.c_str(),ctt.c_str());
        ofstream messout("message.log",ofstream::ate|ofstream::app);
        messout<<pos->message<<endl<<endl;
        printf("%s\n",pos->message);      
      }
      else
        debug_info(pos->message);
      pos = pos->next;
    }
    if(msg != NULL)
      fetion_sip_message_free(msg);
  }
}

void *myKeepalive(void *user)
{
  sleep(waittime);
  for(;;)
  {
    if (sigrelog)
      pthread_exit(NULL);
    if(fetion_user_keep_alive((User *)user) < 0)
    {
      debug_error("Keep alive fail!");
      sigrelog=1;
      pthread_exit(NULL);
    }
    if (sigrelog)
      pthread_exit(NULL);
    sleep(waittime);
  }
  pthread_exit(NULL);
} 

int main(int argc, char *argv[])
{
  int ch;
  char mobileno[BUFLEN];
  char password[BUFLEN];
  char receiveno[BUFLEN];
  char message[BUFLEN];
  string cnum,cpass;
 
  memset(mobileno, 0, sizeof(mobileno));
  memset(password, 0, sizeof(password));
  memset(receiveno, 0, sizeof(receiveno));
  memset(message, 0, sizeof(message));
 
  while((ch = getopt(argc, argv, "c:f:p:t:d:")) != -1) {
    switch(ch) {
    case 'c':
      {
        mobileno_inputed = 1;
        password_inputed = 1;
        ifstream inf(optarg);
        inf>>cnum>>cpass>>ads;
        strncpy(mobileno, cnum.c_str(), sizeof(mobileno) - 1);
        strncpy(password, cpass.c_str(), sizeof(password) - 1);
        break;
      }
    case 'f':
      mobileno_inputed = 1;
      strncpy(mobileno, optarg, sizeof(mobileno) - 1);	
      break;
    case 'p':
      password_inputed = 1;
      strncpy(password, optarg, sizeof(password) - 1);
      break;
    case 't':
      tono_inputed = 1;
      strncpy(receiveno, optarg, sizeof(receiveno) - 1);
      break;
    case 'd':
      message_inputed = 1;
      strncpy(message, optarg, sizeof(message) - 1);
      break;
    default:
      break;
    }
  }
  if(!mobileno_inputed || !password_inputed )
  {
    usage(argv);
    return 1;
  }
  if (message_inputed)
  {
    if(fx_login(mobileno, password))
      return 1;
    if(send_message(mobileno, receiveno, message))
      return 1;
  }
  else
  {
    pthread_attr_t * thAttr = NULL;
    pthread_t tid;
    int ret=0,wait4login=10,isdown=0;
    for (;;)
    {
      failcount=0;
      sigrelog=0;
      ret=fx_login(mobileno, password);
      if (ret)
      {
        debug_info("Login fail!Will login again in %ds",wait4login);
         if (wait4login>640)
        {
          isdown=1;
          mysendmail(ads.c_str(),"您的飞信侦听转发服务离线了","您的飞信转发服务因过去的20分钟内连续登陆失败而下线,系统会继续尝试登录,并在成功后通知您.如果有疑问,请登录服务器人工检查.");
        }
        sleep(wait4login);
        if (!isdown)
          wait4login*=2;
        continue;
      }
      else
        if (isdown)
        {
          mysendmail(ads.c_str(),"您的飞信侦听转发服务恢复了","您的飞信转发服务现在已经恢复运行");
          isdown=0;
          wait4login=10;
        }
      pthread_create(&tid, thAttr, myKeepalive, user);
      recvMsg(user);
      pthread_join(tid,NULL);
      fetion_user_free(user);
      debug_info("Listen fail!Will relogin in 30s!");
      sleep(30);
    }
  }
  fetion_user_free(user);
  return 0;
}
 
static void usage(char *argv[])
{
  fprintf(stderr, "Usage:%s -c Num&PassMailFile -f mobileno -p password -t receive_mobileno -d message\n", argv[0]);
}
