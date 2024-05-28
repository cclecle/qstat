/*
 * qstat
 * by Steve Jankowski
 *
 * New Half-Life2 query protocol
 * Copyright 2005 Ludwig Nussel
 *
 * Licensed under the Artistic License, see LICENSE.txt for license terms
 *
 */

#include <sys/types.h>
#ifndef _WIN32
 #include <sys/socket.h>
 #include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "qstat.h"
#include "packet_manip.h"

#define A2S_GETCHALLENGE				"\xFF\xFF\xFF\xFF\x57"
#define A2S_CHALLENGERESPONSE			0x41
#define A2S_INFO						"\xFF\xFF\xFF\xFF\x54Source Engine Query"
#define A2S_INFORESPONSE_HL2			0x49
#define A2S_PLAYER_EX					"\xFF\xFF\xFF\xFF\x70"
#define A2S_PLAYER_EXRESPONSE			0x71
#define A2S_PLAYER_INVALID_CHALLENGE	"\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF"
#define A2S_RULES						"\xFF\xFF\xFF\xFF\x56"
#define A2S_RULESRESPONSE				0x45

struct a2s_status {
	unsigned sent_challenge : 1;
	unsigned have_challenge : 1;
	unsigned sent_info : 1;
	unsigned have_info : 1;
	unsigned sent_player_ex : 1;
	unsigned have_player_ex : 1;
	unsigned sent_rules : 1;
	unsigned have_rules : 1;
	unsigned challenge;
	unsigned char type;
};

query_status_t
send_a2s_openra_request_packet(struct qserver *server)
{
	struct a2s_status *status = (struct a2s_status *)server->master_query_tag;

	debug(3, "sending info query");
	if (qserver_send_initial(server, A2S_INFO, sizeof(A2S_INFO)) == SOCKET_ERROR) {
		return (DONE_FORCE);
	}

	status->sent_info = 1;
	status->type = 0;

	if (get_server_rules || get_player_info) {
		server->next_rule = ""; // trigger calling send_a2s_rule_request_packet
	}
	return (INPROGRESS);
}


query_status_t
send_a2s_openra_rule_request_packet(struct qserver *server)
{
	struct a2s_status *status = (struct a2s_status *)server->master_query_tag;
	debug(1, "rule request");

	if (!get_server_rules && !get_player_info && status->have_info) {
		debug(1, "force done");
		return (DONE_FORCE);
	}

	if (server->retry1 < 0) {
		debug(1, "too may retries");
		return (DONE_FORCE);
	}

	while (1) {
		if (!status->have_challenge) {
			debug(1, "sending challenge");

			// Challenge Request is deprecated so instead we use an INFO request with an invalid
			// challenge of -1 (0xFFFFFFFF) which prompts the server to send a valid challenge
			char buf[sizeof(A2S_INFO) - 1 + 4] = A2S_INFO;
			// We use a challenge of -1 to ensure compatibility with 3rd party implementations
			// as that's whats documented: https://developer.valvesoftware.com/wiki/Server_queries#Request_Format_5
			status->challenge = -1;
			memcpy(buf + sizeof(A2S_INFO) - 1, &status->challenge, 4);
			if (qserver_send_initial(server, buf, sizeof(buf)) == SOCKET_ERROR) {
				return (SOCKET_ERROR);
			}
			status->sent_challenge = 1;
			break;
		} else if (status->sent_info && !status->have_info) {
			// Need to resend info due to enhanced DDoS protection
			// See: https://steamcommunity.com/discussions/forum/14/2974028351344359625/
			char buf[sizeof(A2S_INFO) + 4] = A2S_INFO;
			memcpy(buf + sizeof(A2S_INFO), &status->challenge, 4);
			debug(1, "sending info query with challenge");
			if (qserver_send_initial(server, buf, sizeof(buf)) == SOCKET_ERROR) {
				return (SOCKET_ERROR);
			}
			break;
		} else if (get_server_rules && !status->have_rules) {
			char buf[sizeof(A2S_RULES) - 1 + 4] = A2S_RULES;
			memcpy(buf + sizeof(A2S_RULES) - 1, &status->challenge, 4);
			debug(1, "sending rule query");
			if (qserver_send_initial(server, buf, sizeof(buf)) == SOCKET_ERROR) {
				return (SOCKET_ERROR);
			}
			status->sent_rules = 1;
			break;
		} else if (get_player_info && !status->have_player_ex) {
			char buf[sizeof(A2S_PLAYER_EX) - 1 + 4] = A2S_PLAYER_EX;
			memcpy(buf + sizeof(A2S_PLAYER_EX) - 1, &status->challenge, 4);
			debug(1, "sending player query");
			if (qserver_send_initial(server, buf, sizeof(buf)) == SOCKET_ERROR) {
				return (SOCKET_ERROR);
			}
			status->sent_player_ex = 1;
			break;
		} else {
			debug(3, "timeout");
			// we are probably called due to timeout, restart.
			status->have_challenge = 0;
			status->have_rules = 0;
		}
	}

	return (INPROGRESS);
}


query_status_t
deal_with_a2s_openra_packet(struct qserver *server, char *rawpkt, int pktlen)
{
	struct a2s_status *status = (struct a2s_status *)server->master_query_tag;
	char *pkt = rawpkt;
	char buf[16];
	char *str;
	unsigned cnt;

	if (server->server_name == NULL) {
		server->ping_total += time_delta(&packet_recv_time, &server->packet_time1);
		server->n_requests++;
	}

	if (pktlen < 5) {
		goto out_too_short;
	}

	if (0 == memcmp(pkt, "\xFE\xFF\xFF\xFF", 4)) {
		// fragmented packet
		unsigned char pkt_index, pkt_max;
		unsigned int pkt_id = 1;
		SavedData *sdata;

		if (pktlen < 9) {
			goto out_too_short;
		}

		pkt += 4;

		// format:
		// int sequenceNumber
		// byte packetId
		// packetId format:
		// bits 0 - 3 = packets position in the sequence ( 0 .. N - 1 )
		// bits 4 - 7 = total number of packets

		// sequenceId
		memcpy(&pkt_id, pkt, 4);
		debug(3, "sequenceId: %d", pkt_id);
		pkt += 4;

		// packetId
		if ((1 == status->type) || (200 > server->protocol_version)) {
			// HL1 format
			// The lower four bits represent the number of packets (2 to 15) and
			// the upper four bits represent the current packet starting with 0
			pkt_max = ((unsigned char)*pkt) & 15;
			pkt_index = ((unsigned char)*pkt) >> 4;
			debug(3, "packetid[1]: 0x%hhx => idx: %hhu, max: %hhu", *pkt, pkt_index, pkt_max);
			pkt++;
			pktlen -= 9;
		} else if (2 == status->type) {
			// HL2 format
			// The next two bytes are:
			// 1. the max packets sent ( byte )
			// 2. the index of this packet starting from 0 ( byte )
			// 3. Size of the split ( short )
			if (pktlen < 10) {
				goto out_too_short;
			}
			pkt_max = ((unsigned char)*pkt);
			pkt_index = ((unsigned char)*(pkt + 1));
			debug(3, "packetid[2]: 0x%hhx => idx: %hhu, max: %hhu", *pkt, pkt_index, pkt_max);
			pkt += 4;
			pktlen -= 12;
		} else {
			malformed_packet(server, "Unable to determine packet format");
			return (PKT_ERROR);
		}

		// pkt_max is the total number of packets expected
		// pkt_index is a bit mask of the packets received.

		if (server->saved_data.data == NULL) {
			sdata = &server->saved_data;
		} else {
			sdata = (SavedData *)calloc(1, sizeof(SavedData));
			sdata->next = server->saved_data.next;
			server->saved_data.next = sdata;
		}

		sdata->pkt_index = pkt_index;
		sdata->pkt_max = pkt_max;
		sdata->pkt_id = pkt_id;
		sdata->datalen = pktlen;
		sdata->data = (char *)malloc(sdata->datalen);
		if (NULL == sdata->data) {
			malformed_packet(server, "Out of memory");
			return (MEM_ERROR);
		}
		memcpy(sdata->data, pkt, sdata->datalen);

		// combine_packets will call us recursively
		return (combine_packets(server));
	} else if (0 != memcmp(pkt, "\xFF\xFF\xFF\xFF", 4)) {
		malformed_packet(server, "invalid packet header");
		return (PKT_ERROR);
	}

	pkt += 4;
	pktlen -= 4;

	pktlen -= 1;
	debug(2, "A2S type = %x", *pkt);
	switch (*pkt++) {
	case A2S_CHALLENGERESPONSE:
		if (pktlen < 4) {
			goto out_too_short;
		}
		memcpy(&status->challenge, pkt, 4);
		// do not count challenge as retry
		if (!status->have_challenge && (server->retry1 != n_retries)) {
			++server->retry1;
			if (server->n_retries) {
				--server->n_retries;
			}
		}
		status->have_challenge = 1;
		debug(3, "challenge %x", status->challenge);
		return (send_a2s_rule_request_packet(server));

	case A2S_INFORESPONSE_HL2:
		if (pktlen < 1) {
			goto out_too_short;
		}
		status->type = 2;
		snprintf(buf, sizeof(buf), "%hhX", *pkt);
		add_rule(server, "protocol", buf, 0);
		++pkt;
		--pktlen;

		// server name
		str = memchr(pkt, '\0', pktlen);
		if (!str) {
			goto out_too_short;
		}
		server->server_name = strdup(pkt);
		pktlen -= str - pkt + 1;
		pkt += str - pkt + 1;

		// map
		str = memchr(pkt, '\0', pktlen);
		if (!str) {
			goto out_too_short;
		}
		server->map_name = strdup(pkt);
		pktlen -= str - pkt + 1;
		pkt += str - pkt + 1;

		// mod
		str = memchr(pkt, '\0', pktlen);
		if (!str) {
			goto out_too_short;
		}
		server->game = strdup(pkt);
		add_rule(server, "gamedir", pkt, 0);
		pktlen -= str - pkt + 1;
		pkt += str - pkt + 1;

		// description
		str = memchr(pkt, '\0', pktlen);
		if (!str) {
			goto out_too_short;
		}
		add_rule(server, "gamename", pkt, 0);
		pktlen -= str - pkt + 1;
		pkt += str - pkt + 1;

		if (pktlen < 9) {
			goto out_too_short;
		}

		// pkt[0], pkt[1] steam appid
		server->protocol_version = (unsigned short)*pkt;
		server->num_players = (unsigned char)pkt[2];
		server->max_players = (unsigned char)pkt[3];
		// pkt[4] number of bots
		sprintf(buf, "%hhu", pkt[4]);
		add_rule(server, "bots", buf, 0);

		add_rule(server, "dedicated", pkt[5] ? "1" : "0", 0);
		if (pkt[6] == 'l') {
			add_rule(server, "sv_os", "linux", 0);
		} else if (pkt[6] == 'w') {
			add_rule(server, "sv_os", "windows", 0);
		} else {
			buf[0] = pkt[6];
			buf[1] = '\0';
			add_rule(server, "sv_os", buf, 0);
		}

		if (pkt[7]) {
			snprintf(buf, sizeof(buf), "%hhu", (unsigned char)pkt[7]);
			add_rule(server, "password", buf, 0);
		}

		if (pkt[8]) {
			snprintf(buf, sizeof(buf), "%hhu", (unsigned char)pkt[8]);
			add_rule(server, "secure", buf, 0);
		}

		pkt += 9;
		pktlen -= 9;

		// version
		str = memchr(pkt, '\0', pktlen);
		if (!str) {
			goto out_too_short;
		}
		add_rule(server, "version", pkt, 0);
		pktlen -= str - pkt + 1;
		pkt += str - pkt + 1;

		// EDF
		if (1 <= pktlen) {
			unsigned char edf = *pkt;
			debug(1, "EDF: 0x%02hhx", edf);
			pkt++;
			pktlen--;
			if (edf & 0x80) {
				// game port
				unsigned short gameport;

				if (pktlen < 2) {
					goto out_too_short;
				}
				gameport = swap_short_from_little(pkt);
				sprintf(buf, "%hu", gameport);
				add_rule(server, "game_port", buf, 0);
				change_server_port(server, gameport, 0);
				pkt += 2;
				pktlen -= 2;
			}

			if (edf & 0x10) {
				// SteamId (long long)
				if (pktlen < 8) {
					goto out_too_short;
				}
				pkt += 8;
				pktlen -= 8;
			}

			if (edf & 0x40) {
				// spectator port
				unsigned short spectator_port;
				if (pktlen < 3) {
					goto out_too_short;
				}
				spectator_port = swap_short_from_little(pkt);
				sprintf(buf, "%hu", spectator_port);
				add_rule(server, "spectator_port", buf, 0);
				pkt += 2;
				pktlen -= 2;

				// spectator server name
				str = memchr(pkt, '\0', pktlen);
				if (!str) {
					goto out_too_short;
				}
				add_rule(server, "spectator_server_name", pkt, 0);
				pktlen -= str - pkt + 1;
				pkt += str - pkt + 1;
			}

			if (edf & 0x20) {
				// Keywords
				str = memchr(pkt, '\0', pktlen);
				if (!str) {
					goto out_too_short;
				}
				add_rule(server, "game_tags", pkt, 0);
				if (strncmp(pkt, "rust", 4) == 0) {
					// Rust is comma seperated tags
					char *keyword = strtok(pkt, ",");
					while (keyword != NULL) {
						if (strncmp(keyword, "cp", 2) == 0) {
							// current players override
							server->num_players = atoi(keyword + 2);
						} else if (strncmp(keyword, "mp", 2) == 0) {
							// max players override
							server->max_players = atoi(keyword + 2);
						}
						keyword = strtok(NULL, ",");
					}
				}
				pktlen -= str - pkt + 1;
				pkt += str - pkt + 1;
			}

			if (edf & 0x01) {
				// GameId (long long)
				if (pktlen < 8) {
					goto out_too_short;
				}
				pkt += 8;
				pktlen -= 8;
			}
		}

		status->have_info = 1;

		server->retry1 = n_retries;

		server->next_player_info = server->num_players;

		break;

	case A2S_RULESRESPONSE:

		if (pktlen < 2) {
			goto out_too_short;
		}

		cnt = (unsigned char)pkt[0] + ((unsigned char)pkt[1] << 8);
		pktlen -= 2;
		pkt += 2;

		debug(3, "num_rules: %d", cnt);

		for ( ; cnt && pktlen > 0; --cnt) {
			char *key, *value;
			str = memchr(pkt, '\0', pktlen);
			if (!str) {
				break;
			}
			key = pkt;
			pktlen -= str - pkt + 1;
			pkt += str - pkt + 1;

			str = memchr(pkt, '\0', pktlen);
			if (!str) {
				break;
			}
			value = pkt;
			pktlen -= str - pkt + 1;
			pkt += str - pkt + 1;

			add_rule(server, key, value, NO_FLAGS);
		}

		if (cnt) {
			malformed_packet(server, "packet contains too few rules, missing %d", cnt);
			server->missing_rules = 1;
		}
		if (pktlen) {
			malformed_packet(server, "garbage at end of rules, %d bytes left", pktlen);
		}

		status->have_rules = 1;

		server->retry1 = n_retries;

		break;

	case A2S_PLAYER_EXRESPONSE:
		if (pktlen < 1) {
			goto out_too_short;
		}

		cnt = *pkt++;
		pktlen --;

		for ( ; cnt && pktlen > 0; --cnt) {

			if (pktlen < 6) {
				goto out_too_short;
			}

			int32_t idx = swap_long_from_little(pkt);
			pkt = pkt+4;
			pktlen = pktlen-4;

			struct player *p = add_player(server, idx);
			if(p)
			{
				int16_t nb_attr = swap_short_from_little(pkt);
				pkt = pkt+2;
				pktlen = pktlen-2;
				
				
				for ( ; nb_attr && pktlen > 0; --nb_attr) {
					uint8_t bIgnoreField = 0;
				
					union _uDataField{
						char* szBuff;
						int8_t i8Var;
						int16_t i16Var;
						int32_t i32Var;
						float f32Var;
					} uDataField;
					
					if (pktlen < 2) {
						goto out_too_short;
					}
					
					uint8_t AttrType = *(int8_t*)pkt++;
					pktlen --;
					
					uint8_t AttrID = *(int8_t*)pkt++;
					pktlen --;

					uint8_t bExtAttribute = (AttrType & 0x80) > 1 ? 1 : 0;
					uint8_t bCustomAttribute = (AttrType & 0x40) > 1 ? 1 : 0;
					uint8_t ExtAttribute = 0;
					if(bExtAttribute)
					{
						if (pktlen < 1) {
							goto out_too_short;
						}
						ExtAttribute = *(int8_t*)pkt++;
						pktlen --;
					}
					bIgnoreField = 0;
					switch(AttrType)
					{
						case 1: // Word8
							if (pktlen < 1) {
								goto out_too_short;
							}
							uDataField.i8Var = *(int8_t*)pkt++;
							pktlen --;
							break;
						case 2: // Word16
							if (pktlen < 2) {
								goto out_too_short;
							}
							uDataField.i16Var = swap_short_from_little(pkt);
							pktlen-=2;
							pkt+=2;
							break;
						case 3: // Word32
							if (pktlen < 4) {
								goto out_too_short;
							}
							uDataField.i32Var = swap_long_from_little(pkt);
							pktlen-=4;
							pkt+=4;
							break;
						case 4: // String
							if (pktlen < 1) {
								goto out_too_short;
							}
							
							str = memchr(pkt, '\0', pktlen);
							if (!str) {
								fprintf(stderr, "Wrong string Attribute\n");
								exit(1);
							}
							uDataField.szBuff = pkt;
							pktlen -= str - pkt + 1;
							pkt += str - pkt + 1;
							break;
						case 5: // Float32
							if (pktlen < 4) {
								goto out_too_short;
							}
							uDataField.f32Var = swap_float_from_little(pkt);
							pktlen-=4;
							pkt+=4;
							break;
						default:
							fprintf(stderr, "Unknown Attribute type\n");
							exit(1);
							break;

					}	

					if(bIgnoreField)
					{	
						continue;
					}

					if(!bCustomAttribute)
					{
						if(!bExtAttribute)
						{
							switch(AttrID)
							{
								case 32: // UUID
									player_add_info_str(p,AttrID,"UUID",uDataField.szBuff,0);
									break;
								case 33: // Name
									p->name = strdup(uDataField.szBuff);
									break;
								case 34: // FullName
									player_add_info_str(p,AttrID,"FullName",uDataField.szBuff,0);
									break;
								case 35: // Ping (ms)
									p->ping = (int)uDataField.i16Var;
									break;
								case 36: // IsInTeam
									player_add_info_bool(p,AttrID,"IsInTeam",uDataField.i8Var,0);
									break;
								case 37: // TeamId
									p->team = (int)uDataField.i8Var;
									break;
								case 38: // Score
									p->score = (int)uDataField.i32Var;
									break;
								case 39: // ConnectionTime (s)
									p->connect_time = (int)uDataField.f32Var;
									break;
								case 40: // IP
									p->address = strdup(uDataField.szBuff);
									break;
								case 41: // IsBot
									if(uDataField.i8Var)
										p->type_flag |= PLAYER_TYPE_BOT;
									break;
								case 42: // IsAdmin
									if(uDataField.i8Var)
										p->type_flag |= PLAYER_TYPE_ADMIN;
									break;
								case 43: // IsSpectating
									if(uDataField.i8Var)
										p->type_flag |= PLAYER_TYPE_SPEC;
									break;
								case 44: // IsAuthenticated
									if(uDataField.i8Var)
										p->type_flag |= PLAYER_TYPE_AUTH;
									break;
								case 45: // Faction
									player_add_info_str(p,AttrID,"Faction",uDataField.szBuff,0);
									break;
								case 64: // Frags
									p->frags = (int)uDataField.i32Var;
									break;
								case 65: // Death
									p->deaths = (int)uDataField.i32Var;
									break;
								case 66: // ACC
									player_add_info_f(p,AttrID,"ACC",uDataField.f32Var,0);
									break;
								case 67: // Efficiency
									player_add_info_f(p,AttrID,"Efficiency",uDataField.f32Var,0);
									break;
								case 96: // APM
									player_add_info_f(p,AttrID,"APM",uDataField.f32Var,0);
									break;
								case 97: // ArmyValue
									player_add_info_i32(p,AttrID,"ArmyValue",uDataField.i32Var,0);
									break;
								case 98: // AssetsValue
									player_add_info_i32(p,AttrID,"AssetsValue",uDataField.i32Var,0);
									break;
								case 99: // BuildingsDead
									player_add_info_i32(p,AttrID,"BuildingsDead",uDataField.i32Var,0);
									break;
								case 100: // BuildingsKilled
									player_add_info_i32(p,AttrID,"BuildingsKilled",uDataField.i32Var,0);
									break;
								case 101: // Earned
									player_add_info_i32(p,AttrID,"Earned",uDataField.i32Var,0);
									break;
								case 102: // UnitsDead
									player_add_info_i32(p,AttrID,"UnitsDead",uDataField.i32Var,0);
									break;
								case 103: // UnitsKilled
									player_add_info_i32(p,AttrID,"UnitsKilled",uDataField.i32Var,0);
									break;
								case 104: // MapExplored
									player_add_info_f(p,AttrID,"MapExplored",uDataField.f32Var,0);
									break;
								default:
									fprintf(stderr, "Unknown Attribute ID\n");
									exit(1);
									break;
							}
						}
					}
				}

				if(p->name == NULL)
					p->name = strdup("UKNOWN PLAYER");

			}
		}

		if (pktlen) {
			malformed_packet(server, "garbage at end of player info, %d bytes left", pktlen);
		}

		status->have_player_ex = 1;
		// Workaround broken implementations which don't send a challenge to a player request
		// that hasn't seen a challenge yet. Without this we would end up in an infinite loop.
		if (status->have_challenge == 0) {
			if (show_errors) {
				fprintf(stderr, "server has broken challenge so is a DDoS source!\n");
			}
			status->have_challenge = 1;
		}

		server->retry1 = n_retries;

		break;
		
	default:
		malformed_packet(server, "invalid packet id %hhx", *--pkt);
		return (PKT_ERROR);
	}

	if (
		(!get_player_info || (get_player_info && status->have_player_ex)) &&
		(!get_server_rules || (get_server_rules && status->have_rules))
		) {
		server->next_rule = NULL;
	}

	return (DONE_AUTO);

out_too_short:
	malformed_packet(server, "packet too short");
	return (PKT_ERROR);
}


// vim: sw=4 ts=4 noet
