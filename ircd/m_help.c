/*
 * Aide sur les principales fonctions du serveur IrcDreams V2
 * m_help - Refait par BuGs
 * 
 * parv[0] = sender prefix
 * parv[1] = topic
 */

#include "../config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "ircd_features.h"
#include "version.h"

#include <assert.h>
#include <string.h>

int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int i;

  if (parc < 2)
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :\002Bienvenue dans l'aide IrcDreams\002", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Vous trouverez ici de multiples informations relatives", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :aux diff�rents modes et commandes", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :-", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Voici les diff�rents menus auxquels vous avez acc�s :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   UMODES - Liste les modes utilisateurs et en donne une br�ve description.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   CHMODES - Liste les modes salons et en donne une br�ve description.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   CMDS - Liste compl�te des commandes.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Utilisez /quote help <option>", sptr);
    return 0;
  }
  if (!strcasecmp("chmodes", parv[1]))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Liste des modes salons :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+s : Salon secret, le salon n'est pas affich� dans les whois ni dans la liste des canaux", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+p : Salon personnel, pareil que +s", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+m : Seuls les voic�s et op�rateurs peuvent parler", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+t : Seuls les op�rateurs peuvent changer le sujet du salon (topic)", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+i : N�cessite une invitation pour entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+n : Emp�che les utilisateurs qui ne sont pas dans le salon d'y envoyer un message", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+C : Emp�che d'utiliser les ctcp salons", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+c : Enl�ve les couleurs des messages", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+N : Emp�che d'envoyer des notices sur le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+q : Enl�ve les messages de Part/Quit du salon.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+D : Mode Auditorium. Les Join/Part/Quit sont supprim� sauf pour les utilisateurs actifs", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+R : Seuls les utilisateurs identifi�s � votre service irc peuvent parler dans le salon",sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+O : Emp�che les non IRCops d'entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+T : Emp�che de recevoir sur le salon les messages multi-cibles (/AMSG par exemple)", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+M : Transforme les majuscules en minuscules", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+P : Supprime les publicit�s pour des salons", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+W : Supprime les publicit�s pour des sites internet", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+r : Seuls les utilisateurs identifi�s � votre service irc peuvent entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+l <nb> : Fixe une limite d'utilisateurs", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+k <pass> : D�fini un mot de passe pour entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+o <pseudo> : Donne le statut d'op�rateur un utilistateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+h <pseudo> : Donne le statut de halfop�rateur � un utilisateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+v <pseudo> : Donne le statut de voice � un utilisateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+b <mask> : Banni un mask", sptr);
    return 0;
  }
  if (!strcasecmp("umodes", parv[1]))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Liste des modes pour utilisateurs et IRCops :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+a : Mode des IRC Administrateurs.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+c : Mode des IRC Co-Administrateurs.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+d : Permet de ne plus recevoir les msg des salons.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+f : D�fini votre sexe comme f�minin.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+g : Mode de debug.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+h : D�fini votre sexe comme masculin.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+i : Permet d'�tre cach� dans WHO et NAMES.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+k : Mode des robots, qui permet de pas �tre kick, deop ou kill, et d'autres commandes pour services.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+o : Mode des IRCops", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+r : Mode des utilisateurs identifi�s � votre service irc", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+s : Permet de voir les snotices", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+w : Permet de voir les wallops", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+x : Permet d'avoir un host en %s.%s une fois identifi� � votre service irc", sptr, parv[0], feature_str(FEAT_HIDDEN_HOST));
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+A : Mode Helpeur Officiel", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+H : Mode r�serv� pour le vhost.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+P : Permet de ne pas recevoir de messages Priv�s.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+R : Seuls les utilisateurs identifi�s � votre service irc peuvent vous envoyer des notices ou des messages priv�s.", sptr);
    if (IsAnOper(sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :---", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Modes IRCops:", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+C : Emp�che les utilisateurs de voir la liste de salons actuels", sptr); 
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+D : Mode obligatoire pour red�marrer (restart) ou couper (die) le serveur.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+I : Emp�che les utilisateurs de voir l'idle.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+S : Emp�che les utilisateurs de voir votre status d'ircop.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+X : Permet d'�tre totalement invisible sur le serveur.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+W : Permet de voir la personne qui demande des information sur vous (/WHOIS).", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+Z :  Mode Dieu. Permet de passer � travers TOUS les modes qui bloqueraient un utilisateur normal et de se prot�ger.", sptr);
    }
    return 0;
  }
  if (!strcasecmp("cmds", parv[1]))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :\002Liste des commandes :\002", sptr);
   
    for (i = 0; msgtab[i].cmd; i++)
    	sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, msgtab[i].cmd);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Fin de la liste des %d commandes.", sptr, (i - 1));
    return 0;
  }
  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :La commande demand�e n'a pas �t� trouv�e.",sptr);
  return 0;
}
