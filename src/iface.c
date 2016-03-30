/*-
 * Copyright (c) 1998 Brian Somers <brian@Awfulhak.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/usr.sbin/ppp/iface.c 281143 2015-04-06 09:42:23Z glebius $
 */

#define NOINET6

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <netinet/ip.h>

#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <termios.h>
#include <unistd.h>

#include "layer.h"
#include "defs.h"
#include "command.h"
#include "mbuf.h"
#include "log.h"
#include "id.h"
#include "timer.h"
#include "fsm.h"
#include "iplist.h"
#include "lqr.h"
#include "hdlc.h"
#include "throughput.h"
#include "slcompress.h"
#include "descriptor.h"
#include "ncpaddr.h"
#include "ipcp.h"
#include "filter.h"
#include "lcp.h"
#include "ccp.h"
#include "link.h"
#include "mp.h"
#ifndef NORADIUS
#include "radius.h"
#endif
//#include "ipv6cp.h"
#include "ncp.h"
#include "bundle.h"
#include "prompt.h"
#include "iface.h"

#define IN6MASK128	{{{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}}
static const struct in6_addr in6mask128 = IN6MASK128;


struct iface *
iface_Create(const char *name, int fd)
{
  int  err;

  struct iface *iface;
  struct iface_addr *addr;
  struct ifreq ifr;

  strncpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  err = 0;

  if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
      err = errno;
      printf("create tun error %s\n", strerror(err));
      return NULL;
  }

  iface = (struct iface *)malloc(sizeof *iface);
  if (iface == NULL) {
	fprintf(stderr, "iface_Create: malloc: %s\n", strerror(errno));
	return NULL;
  }
  iface->name = strdup(name);
  iface->descr = NULL;
  iface->index = ifr.ifr_ifindex ;
  iface->flags = ifr.ifr_flags;
  iface->mtu = 0;
  iface->addrs = 0;
  iface->addr = NULL;

  /* Record the address */

  addr = (struct iface_addr *)
	realloc(iface->addr, (iface->addrs + 1) * sizeof iface->addr[0]);
  if (addr == NULL)
	return NULL;
  iface->addr = addr;

  addr += iface->addrs;
  iface->addrs++;
  ncprange_setsa(&addr->ifa, &ifr.ifr_addr, &ifr.ifr_netmask);
  ncpaddr_setsa(&addr->peer, &ifr.ifr_dstaddr);
  printf("my addr: %X, dst addr %X\n", addr->ifa.u.ip4.ipaddr.s_addr, addr->peer.u.ip4addr.s_addr);
  return iface;
}

static int
iface_addr_Zap(const char *name, struct iface_addr *addr, int s)
{
  struct ifreq ifreq;
  struct sockaddr_in *me4, *msk4, *peer4;
  struct sockaddr_storage ssme, sspeer, ssmsk;
  int res;

  TRACE;

  printf("name %s, addr my %X his %X\n", name, addr->ifa.u.ip4.ipaddr.s_addr, addr->peer.u.ip4addr.s_addr);

  ncprange_getsa(&addr->ifa, &ssme, &ssmsk);
  ncpaddr_getsa(&addr->peer, &sspeer);
  res = 0;

  switch (ncprange_family(&addr->ifa)) {
  case AF_INET:
    memset(&ifreq, '\0', sizeof ifreq);
    strncpy(ifreq.ifr_name, name, IFNAMSIZ);

    me4 = (struct sockaddr_in *)&ifreq.ifr_addr;
    memcpy(me4, &ssme, sizeof *me4);

    msk4 = (struct sockaddr_in *)&ifreq.ifr_netmask;
    memcpy(msk4, &ssmsk, sizeof *msk4);

    peer4 = (struct sockaddr_in *)&ifreq.ifr_broadaddr;
    if (ncpaddr_family(&addr->peer) == AF_UNSPEC) {
      peer4->sin_family = AF_INET;
      peer4->sin_addr.s_addr = INADDR_NONE;
    } else
      memcpy(peer4, &sspeer, sizeof *peer4);

//    printf("ifreq my %X, broad %X\n", (unsigned long long int)ifreq.ifr_addr.sa_data, (unsigned long long int)ifreq.ifr_broadaddr.sa_data);

    res = ID0ioctl(s, SIOCDIFADDR, &ifreq);
    if (log_IsKept(LogDEBUG)) {
      char buf[100];

      snprintf(buf, sizeof buf, "%s", ncprange_ntoa(&addr->ifa));
      log_Printf(LogWARN, "%s: DIFADDR %s -> %s returns %d\n",
                 ifreq.ifr_name, buf, ncpaddr_ntoa(&addr->peer), res);
    }
    break;

  }

  if (res == -1) {
    char dst[40];
    const char *end =
#ifndef NOINET6
      ncprange_family(&addr->ifa) == AF_INET6 ? "_IN6" :
#endif
      "";

    if (ncpaddr_family(&addr->peer) == AF_UNSPEC)
      log_Printf(LogWARN, "iface rm: ioctl(SIOCDIFADDR%s, %s): %s\n",
                 end, ncprange_ntoa(&addr->ifa), strerror(errno));
    else {
      snprintf(dst, sizeof dst, "%s", ncpaddr_ntoa(&addr->peer));
      log_Printf(LogWARN, "iface rm: ioctl(SIOCDIFADDR%s, %s -> %s): %s\n",
                 end, ncprange_ntoa(&addr->ifa), dst, strerror(errno));
    }
  }

  return res != -1;
	return 0;
}

static int
iface_addr_Add(const char *name, struct iface_addr *addr, int s)
{
  struct ifreq ifreq;
  struct sockaddr_in *me4, *msk4, *peer4;
  struct sockaddr_storage ssme, sspeer, ssmsk;
  int res;

  TRACE;

  ncprange_getsa(&addr->ifa, &ssme, &ssmsk);
  ncpaddr_getsa(&addr->peer, &sspeer);
  res = 0;

  printf("name %s, addr my %X his %X\n", name, addr->ifa.u.ip4.ipaddr.s_addr, addr->peer.u.ip4addr.s_addr);

  switch (ncprange_family(&addr->ifa)) {
  case AF_INET:
    memset(&ifreq, '\0', sizeof ifreq);
    strncpy(ifreq.ifr_name, name, IFNAMSIZ);

    me4 = (struct sockaddr_in *)&ifreq.ifr_addr;
    me4->sin_addr.s_addr = addr->ifa.u.ip4.ipaddr.s_addr; /*network byte order*/
    me4->sin_family = AF_INET;

    printf("1 my %X\n", ((struct sockaddr_in *)(&ifreq.ifr_addr))->sin_addr.s_addr);

    res = ID0ioctl(s, SIOCSIFADDR, &ifreq);
    if (log_IsKept(LogDEBUG)) {
      char buf[100];

      snprintf(buf, sizeof buf, "%s", ncprange_ntoa(&addr->ifa));
      log_Printf(LogWARN, "%s: AIFADDR %s -> %s returns %d\n",
                 ifreq.ifr_name, buf, ncpaddr_ntoa(&addr->peer), res);
    }
    msk4 = (struct sockaddr_in *)&ifreq.ifr_netmask;
    msk4->sin_addr.s_addr = addr->ifa.u.ip4.mask.s_addr; /*network byte order*/
    msk4->sin_family = AF_INET;
    printf("mask %X\n", ((struct sockaddr_in *)(&ifreq.ifr_addr))->sin_addr.s_addr);


    res = ID0ioctl(s, SIOCSIFNETMASK, &ifreq);
    if (log_IsKept(LogDEBUG)) {
      char buf[100];

      snprintf(buf, sizeof buf, "%s", ncprange_ntoa(&addr->ifa));
      log_Printf(LogWARN, "%s: AIFADDR %s -> %s returns %d\n",
                 ifreq.ifr_name, buf, ncpaddr_ntoa(&addr->peer), res);
    }


    //peer4 = (struct sockaddr_in *)&ifreq.ifr_broadaddr; //SIOCSIFBRDADDR
    peer4 = (struct sockaddr_in *)&ifreq.ifr_dstaddr;
    peer4->sin_family = AF_INET;
    if (ncpaddr_family(&addr->peer) == AF_UNSPEC) {
      peer4->sin_addr.s_addr = INADDR_NONE;
    } else{
    	peer4->sin_addr.s_addr = addr->peer.u.ip4addr.s_addr; /*network byte order*/
    }

    printf("peer %X\n", ((struct sockaddr_in *)(&ifreq.ifr_dstaddr))->sin_addr.s_addr);

    res = ID0ioctl(s, SIOCSIFDSTADDR, &ifreq);
    if (log_IsKept(LogDEBUG)) {
      char buf[100];

      snprintf(buf, sizeof buf, "%s", ncprange_ntoa(&addr->ifa));
      log_Printf(LogWARN, "%s: AIFADDR %s -> %s returns %d\n",
                 ifreq.ifr_name, buf, ncpaddr_ntoa(&addr->peer), res);
    }
    break;

  }

  if (res == -1) {
    char dst[40];
    const char *end =
#ifndef NOINET6
      ncprange_family(&addr->ifa) == AF_INET6 ? "_IN6" :
#endif
      "";

    if (ncpaddr_family(&addr->peer) == AF_UNSPEC)
      log_Printf(LogWARN, "iface add: ioctl(SIOCAIFADDR%s, %s): %s\n",
                 end, ncprange_ntoa(&addr->ifa), strerror(errno));
    else {
      snprintf(dst, sizeof dst, "%s", ncpaddr_ntoa(&addr->peer));
      log_Printf(LogWARN, "iface add: ioctl(SIOCAIFADDR%s, %s -> %s): %s\n",
                 end, ncprange_ntoa(&addr->ifa), dst, strerror(errno));
    }
  }

  return res != -1;
}

int
iface_Name(struct iface *iface, const char *name)
{
  struct ifreq ifr;
  int s;
  char *newname;

  if ((newname = strdup(name)) == NULL) {
    log_Printf(LogWARN, "iface name: strdup failed: %s\n", strerror(errno));
    return 0;
  }

  if ((s = ID0socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
    log_Printf(LogERROR, "iface name: socket(): %s\n", strerror(errno));
    free(newname);
    return 0;
  }

  strncpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
  ifr.ifr_data = newname;
  if (ID0ioctl(s, SIOCSIFNAME, (caddr_t)&ifr) < 0) {
    log_Printf(LogWARN, "iface name: ioctl(SIOCSIFNAME, %s -> %s): %s\n",
               name, newname, strerror(errno));
    free(newname);
    return 0;
  }

  free(iface->name);
  iface->name = newname;

  return 1;
}

int
iface_Descr(struct cmdargs const *arg)
{

  return 0;
}

void
iface_Clear(struct iface *iface, struct ncp *ncp, int family, int how)
{
  int af, inskip, in6skip, s4 = -1, s6 = -1, *s;
  unsigned n;

  TRACE;

  if (iface->addrs) {
    inskip = in6skip = how == IFACE_CLEAR_ALL ? 0 : 1;

    for (n = 0; n < iface->addrs; n++) {
      af = ncprange_family(&iface->addr[n].ifa);
      if (family == 0 || family == af) {
        if (!iface->addr[n].system && (how & IFACE_SYSTEM))
          continue;
        switch (af) {
        case AF_INET:
          if (inskip) {
            inskip = 0;
            continue;
          }
          s = &s4;
          break;

#ifndef NOINET6
        case AF_INET6:
          if (in6skip) {
            in6skip = 0;
            continue;
          }
          s = &s6;
          break;
#endif
        default:
          continue;
        }

        if (*s == -1 && (*s = ID0socket(af, SOCK_DGRAM, 0)) == -1)
          log_Printf(LogERROR, "iface_Clear: socket(): %s\n", strerror(errno));
        else if (iface_addr_Zap(iface->name, iface->addr + n, *s)) {
          ncp_IfaceAddrDeleted(ncp, iface->addr + n);
          bcopy(iface->addr + n + 1, iface->addr + n,
                (iface->addrs - n - 1) * sizeof *iface->addr);
          iface->addrs--;
          n--;
        }
      }
    }

    /* Don't bother realloc()ing - we have little to gain */

    if (s4)
      close(s4);
    if (s6)
      close(s6);
  }
}

int
iface_Add(struct iface *iface, struct ncp *ncp, const struct ncprange *ifa,
          const struct ncpaddr *peer, int how)
{
  int af, removed, s;
  unsigned n;
  struct ncpaddr ncplocal;
  struct iface_addr *addr, newaddr;

  TRACE;

  af = ncprange_family(ifa);
  if ((s = ID0socket(af, SOCK_DGRAM, 0)) == -1) {
    log_Printf(LogERROR, "iface_Add: socket(): %s\n", strerror(errno));
    return 0;
  }
  ncprange_getaddr(ifa, &ncplocal);

  for (n = 0; n < iface->addrs; n++) {
	printf("n = %d\n", n);
    if (ncprange_contains(&iface->addr[n].ifa, &ncplocal) ||
        ncpaddr_equal(&iface->addr[n].peer, peer)) {
    	printf("Replace this sockaddr\n");
		  if (!(how & IFACE_FORCE_ADD)) {
			printf("close 1\n");
			close(s);
			return 0;	/* errno = EEXIST; */
		  }

		  if (ncprange_equal(&iface->addr[n].ifa, ifa) &&
			  ncpaddr_equal(&iface->addr[n].peer, peer)) {
			printf("close 2\n");
			close(s);
			ncp_IfaceAddrAdded(ncp, iface->addr + n);
			return 1;	/* Already there */
		  }

		  removed = iface_addr_Zap(iface->name, iface->addr + n, s);
		  if (removed)
			ncp_IfaceAddrDeleted(ncp, iface->addr + n);
		  ncprange_copy(&iface->addr[n].ifa, ifa);
		  ncpaddr_copy(&iface->addr[n].peer, peer);
		  if (!iface_addr_Add(iface->name, iface->addr + n, s)) {
			if (removed) {
			  bcopy(iface->addr + n + 1, iface->addr + n,
					(iface->addrs - n - 1) * sizeof *iface->addr);
			  iface->addrs--;
			  n--;
			}
			printf("close 3\n");
			close(s);
			return 0;
		  }
      close(s);
      printf("close 4\n");
      ncp_IfaceAddrAdded(ncp, iface->addr + n);
      return 1;
    }
  }

  addr = (struct iface_addr *)realloc
    (iface->addr, (iface->addrs + 1) * sizeof iface->addr[0]);
  if (addr == NULL) {
    log_Printf(LogERROR, "iface_inAdd: realloc: %s\n", strerror(errno));
    close(s);
    return 0;
  }
  iface->addr = addr;

  ncprange_copy(&newaddr.ifa, ifa);
  ncpaddr_copy(&newaddr.peer, peer);
  newaddr.system = !!(how & IFACE_SYSTEM);
  if (!iface_addr_Add(iface->name, &newaddr, s)) {
    close(s);
    return 0;
  }

  if (how & IFACE_ADD_FIRST) {
    /* Stuff it at the start of our list */
    n = 0;
    bcopy(iface->addr, iface->addr + 1, iface->addrs * sizeof *iface->addr);
  } else
    n = iface->addrs;

  iface->addrs++;
  memcpy(iface->addr + n, &newaddr, sizeof(*iface->addr));

  close(s);
  ncp_IfaceAddrAdded(ncp, iface->addr + n);

  return 1;
}

int
iface_Delete(struct iface *iface, struct ncp *ncp, const struct ncpaddr *del)
{
  struct ncpaddr found;
  unsigned n;
  int res, s;

  if ((s = ID0socket(ncpaddr_family(del), SOCK_DGRAM, 0)) == -1) {
    log_Printf(LogERROR, "iface_Delete: socket(): %s\n", strerror(errno));
    return 0;
  }

  for (n = res = 0; n < iface->addrs; n++) {
    ncprange_getaddr(&iface->addr[n].ifa, &found);
    if (ncpaddr_equal(&found, del)) {
      if (iface_addr_Zap(iface->name, iface->addr + n, s)) {
        ncp_IfaceAddrDeleted(ncp, iface->addr + n);
        bcopy(iface->addr + n + 1, iface->addr + n,
              (iface->addrs - n - 1) * sizeof *iface->addr);
        iface->addrs--;
        res = 1;
      }
      break;
    }
  }

  close(s);

  return res;
}

#define IFACE_ADDFLAGS 1
#define IFACE_DELFLAGS 2

static int
iface_ChangeFlags(const char *ifname, int flags, int how)
{
  struct ifreq ifrq;
  int s, new_flags;

  TRACE;

  s = ID0socket(PF_INET, SOCK_DGRAM, 0);
  if (s < 0) {
    log_Printf(LogERROR, "iface_ChangeFlags: socket: %s\n", strerror(errno));
    return 0;
  }

  memset(&ifrq, '\0', sizeof ifrq);
  strncpy(ifrq.ifr_name, ifname, sizeof ifrq.ifr_name - 1);
  ifrq.ifr_name[sizeof ifrq.ifr_name - 1] = '\0';
  if (ID0ioctl(s, SIOCGIFFLAGS, &ifrq) < 0) {
    log_Printf(LogERROR, "iface_ChangeFlags: ioctl(SIOCGIFFLAGS): %s\n",
       strerror(errno));
    close(s);
    return 0;
  }
#ifdef __FreeBSD__
  new_flags = (ifrq.ifr_flags & 0xffff) | (ifrq.ifr_flagshigh << 16);
#else
  new_flags = ifrq.ifr_flags & 0xffff;
#endif

  if (how == IFACE_ADDFLAGS)
    new_flags |= flags;
  else
    new_flags &= ~flags;
  ifrq.ifr_flags = new_flags & 0xffff;
#ifdef __FreeBSD__
  ifrq.ifr_flagshigh = new_flags >> 16;
#endif

  if (ID0ioctl(s, SIOCSIFFLAGS, &ifrq) < 0) {
    log_Printf(LogERROR, "iface_ChangeFlags: ioctl(SIOCSIFFLAGS): %s\n",
       strerror(errno));
    close(s);
    return 0;
  }
  close(s);

  return 1;	/* Success */
}

int
iface_SetFlags(const char *ifname, int flags)
{
  return iface_ChangeFlags(ifname, flags, IFACE_ADDFLAGS);
}

int
iface_ClearFlags(const char *ifname, int flags)
{
  return iface_ChangeFlags(ifname, flags, IFACE_DELFLAGS);
}

void
iface_Free(struct iface *iface)
{
    free(iface->name);
    free(iface->descr);
    free(iface->addr);
    free(iface);
}

void
iface_Destroy(struct iface *iface)
{
  struct ifreq ifr;
  int s;

  if (iface != NULL) {
    if ((s = ID0socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
      log_Printf(LogERROR, "iface_Destroy: socket(): %s\n", strerror(errno));
    } else {
      strncpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name));
      if (ID0ioctl(s, TUNSETPERSIST, 0) < 0)
        log_Printf(LogWARN, "iface_Destroy: ioctl(SIOCIFDESTROY, %s): %s\n",
               iface->name, strerror(errno));
    }
    iface_Free(iface);
  }
}

#define if_entry(x) { IFF_##x, #x }

struct {
  int flag;
  const char *value;
} if_flags[] = {
  if_entry(UP),
  if_entry(BROADCAST),
  if_entry(DEBUG),
  if_entry(LOOPBACK),
  if_entry(POINTOPOINT),
  if_entry(RUNNING),
  if_entry(NOARP),
  if_entry(PROMISC),
  if_entry(ALLMULTI),
  if_entry(MULTICAST),
  { 0, "???" }
};

int
iface_Show(struct cmdargs const *arg)
{
  struct ncpaddr ncpaddr;
  struct iface *iface = arg->bundle->iface;
  unsigned f;
  int flags;
#ifndef NOINET6
  int scopeid, width;
#endif
  struct in_addr mask;

  flags = iface->flags;

  prompt_Printf(arg->prompt, "%s (idx %d) <", iface->name, iface->index);
  for (f = 0; f < sizeof if_flags / sizeof if_flags[0]; f++)
    if ((if_flags[f].flag & flags)) {
      prompt_Printf(arg->prompt, "%s%s", flags == iface->flags ? "" : ",",
                    if_flags[f].value);
      flags &= ~if_flags[f].flag;
    }

#if 0
  if (flags)
    prompt_Printf(arg->prompt, "%s0x%x", flags == iface->flags ? "" : ",",
                  flags);
#endif

  prompt_Printf(arg->prompt, "> mtu %lu has %d address%s:\n", iface->mtu,
                iface->addrs, iface->addrs == 1 ? "" : "es");

  for (f = 0; f < iface->addrs; f++) {
    ncprange_getaddr(&iface->addr[f].ifa, &ncpaddr);
    switch (ncprange_family(&iface->addr[f].ifa)) {
    case AF_INET:
      prompt_Printf(arg->prompt, "  inet %s --> ", ncpaddr_ntoa(&ncpaddr));
      if (ncpaddr_family(&iface->addr[f].peer) == AF_UNSPEC)
        prompt_Printf(arg->prompt, "255.255.255.255");
      else
        prompt_Printf(arg->prompt, "%s", ncpaddr_ntoa(&iface->addr[f].peer));
      ncprange_getip4mask(&iface->addr[f].ifa, &mask);
      prompt_Printf(arg->prompt, " netmask 0x%08lx", (long)ntohl(mask.s_addr));
      break;

#ifndef NOINET6
    case AF_INET6:
      prompt_Printf(arg->prompt, "  inet6 %s", ncpaddr_ntoa(&ncpaddr));
      if (ncpaddr_family(&iface->addr[f].peer) != AF_UNSPEC)
        prompt_Printf(arg->prompt, " --> %s",
                      ncpaddr_ntoa(&iface->addr[f].peer));
      ncprange_getwidth(&iface->addr[f].ifa, &width);
      if (ncpaddr_family(&iface->addr[f].peer) == AF_UNSPEC)
        prompt_Printf(arg->prompt, " prefixlen %d", width);
      if ((scopeid = ncprange_scopeid(&iface->addr[f].ifa)) != -1)
        prompt_Printf(arg->prompt, " scopeid 0x%x", (unsigned)scopeid);
      break;
#endif
    }
    prompt_Printf(arg->prompt, "\n");
  }

  return 0;
}

//void
//iface_ParseHdr(struct ifa_msghdr *ifam, struct sockaddr *sa[RTAX_MAX])
//{
//  char *wp;
//  int rtax;
//
//  wp = (char *)(ifam + 1);
//
//  for (rtax = 0; rtax < RTAX_MAX; rtax++)
//    if (ifam->ifam_addrs & (1 << rtax)) {
//      sa[rtax] = (struct sockaddr *)wp;
//      wp += ROUNDUP(sa[rtax]->sa_len);
//    } else
//      sa[rtax] = NULL;
//}
