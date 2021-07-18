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
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :aux différents modes et commandes", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :-", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Voici les différents menus auxquels vous avez accès :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   UMODES - Liste les modes utilisateurs et en donne une brève description.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   CHMODES - Liste les modes salons et en donne une brève description.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :   CMDS - Liste complète des commandes.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Utilisez /quote help <option>", sptr);
    return 0;
  }
  if (!strcasecmp("chmodes", parv[1]))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Liste des modes salons :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+s : Salon secret, le salon n'est pas affiché dans les whois ni dans la liste des canaux", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+p : Salon personnel, pareil que +s", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+m : Seuls les voicés et opérateurs peuvent parler", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+t : Seuls les opérateurs peuvent changer le sujet du salon (topic)", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+i : Nécessite une invitation pour entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+n : Empêche les utilisateurs qui ne sont pas dans le salon d'y envoyer un message", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+C : Empêche d'utiliser les ctcp salons", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+c : Enlève les couleurs des messages", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+N : Empêche d'envoyer des notices sur le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+q : Enlève les messages de Part/Quit du salon.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+D : Mode Auditorium. Les Join/Part/Quit sont supprimé sauf pour les utilisateurs actifs", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+R : Seuls les utilisateurs identifiés à votre service irc peuvent parler dans le salon",sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+O : Empêche les non IRCops d'entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+T : Empêche de recevoir sur le salon les messages multi-cibles (/AMSG par exemple)", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+M : Transforme les majuscules en minuscules", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+P : Supprime les publicités pour des salons", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+W : Supprime les publicités pour des sites internet", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+r : Seuls les utilisateurs identifiés à votre service irc peuvent entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+l <nb> : Fixe une limite d'utilisateurs", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+k <pass> : Défini un mot de passe pour entrer dans le salon", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+o <pseudo> : Donne le statut d'opérateur un utilistateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+h <pseudo> : Donne le statut de halfopérateur à un utilisateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+v <pseudo> : Donne le statut de voice à un utilisateur", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+b <mask> : Banni un mask", sptr);
    return 0;
  }
  if (!strcasecmp("umodes", parv[1]))
  {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Liste des modes pour utilisateurs et IRCops :", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+a : Mode des IRC Administrateurs.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+c : Mode des IRC Co-Administrateurs.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+d : Permet de ne plus recevoir les msg des salons.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+f : Défini votre sexe comme féminin.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+g : Mode de debug.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+h : Défini votre sexe comme masculin.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+i : Permet d'être caché dans WHO et NAMES.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+k : Mode des robots, qui permet de pas être kick, deop ou kill, et d'autres commandes pour services.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+o : Mode des IRCops", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+r : Mode des utilisateurs identifiés à votre service irc", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+s : Permet de voir les snotices", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+w : Permet de voir les wallops", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+x : Permet d'avoir un host en %s.%s une fois identifié à votre service irc", sptr, parv[0], feature_str(FEAT_HIDDEN_HOST));
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+A : Mode Helpeur Officiel", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+H : Mode réservé pour le vhost.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+P : Permet de ne pas recevoir de messages Privés.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+R : Seuls les utilisateurs identifiés à votre service irc peuvent vous envoyer des notices ou des messages privés.", sptr);
    if (IsAnOper(sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :---", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Modes IRCops:", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+C : Empêche les utilisateurs de voir la liste de salons actuels", sptr); 
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+D : Mode obligatoire pour redémarrer (restart) ou couper (die) le serveur.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+I : Empêche les utilisateurs de voir l'idle.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+S : Empêche les utilisateurs de voir votre status d'ircop.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+X : Permet d'être totalement invisible sur le serveur.", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+W : Permet de voir la personne qui demande des information sur vous (/WHOIS).", sptr);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :+Z :  Mode Dieu. Permet de passer à travers TOUS les modes qui bloqueraient un utilisateur normal et de se protéger.", sptr);
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
  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :La commande demandée n'a pas été trouvée.",sptr);
  return 0;
}
