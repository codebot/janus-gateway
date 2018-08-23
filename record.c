/*! \file    record.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Audio/Video recorder
 * \details  Implementation of a simple recorder utility that plugins
 * can make use of to record audio/video frames to a Janus file. This
 * file just saves RTP frames in a structured way, so that they can be
 * post-processed later on to get a valid container file (e.g., a .opus
 * file for Opus audio or a .webm file for VP8 video) and keep things
 * simpler on the plugin and core side.
 * \note If you want to record both audio and video, you'll have to use
 * two different recorders. Any muxing in the same container will have
 * to be done in the post-processing phase.
 * 
 * \ingroup core
 * \ref core
 */
 
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <glib.h>
#include <jansson.h>

#include "record.h"
#include "debug.h"
#include "utils.h"

#define htonll(x) ((1==htonl(1)) ? (x) : ((gint64)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((gint64)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


/* Info header in the structured recording */
static const char *header = "MJR00001";
/* Frame header in the structured recording */
static const char *frame_header = "MEETECHO";

/* Whether the filenames should have a temporary extension, while saving, or not (default=false) */
static gboolean rec_tempname = FALSE;
/* Extension to add in case tempnames is true (default="tmp" --> ".tmp") */
static char *rec_tempext = NULL;
/* Public key used to encrypt the recordings */
static EVP_PKEY *rec_pubkey = NULL;

static gboolean janus_recorder_write(
		janus_recorder *recorder,
		const void * const buffer, const size_t nbytes);

/********************************************************************/

static gboolean janus_recorder_write(
		janus_recorder *recorder, const void * const buffer,
		const size_t nbytes) {
	const unsigned char * const cptr = (const unsigned char * const)buffer;
	if (!rec_pubkey) {
		int bytes_remaining = nbytes;
		while(bytes_remaining > 0) {
			const int rc = fwrite(cptr+nbytes-bytes_remaining, 1,
					bytes_remaining, recorder->file);
			if(rc <= 0) {
				JANUS_LOG(LOG_ERR, "fwrite error in janus_recorder_write!\n");
				/* todo: better error message */
				return FALSE;
			}
			bytes_remaining -= rc;
		}
    return TRUE;
		//if (fwrite(ptr, 1, nbytes, recorder->file) != nbytes) {
			/* todo: print error message to log */
		//	return FALSE;
		//}
	} else {
		const size_t BLOCK_LEN = 16;
		/* worst case, we are one byte beyond a block boundary... */
		const size_t required_ciphertext_buffer_len =
				((nbytes + BLOCK_LEN - 1) / BLOCK_LEN) * BLOCK_LEN;
		/* if needed, allocate a larger buffer */
		if (required_ciphertext_buffer_len > recorder->ciphertext_buffer_len) {
			JANUS_LOG(LOG_INFO, "Growing ciphertext buffer from %d to %d\n",
					(int)recorder->ciphertext_buffer_len,
					(int)required_ciphertext_buffer_len);
			if (recorder->ciphertext_buffer) {
				g_free(recorder->ciphertext_buffer);
			}
			recorder->ciphertext_buffer = g_malloc0(required_ciphertext_buffer_len);
			recorder->ciphertext_buffer_len = required_ciphertext_buffer_len;
		}
		int evp_outlen = 0;
		if (1 != EVP_SealUpdate(recorder->evp_ctx, recorder->ciphertext_buffer,
					&evp_outlen, cptr, nbytes)) {
			JANUS_LOG(LOG_ERR, "Error enciphering data: %s\n",
					ERR_error_string(ERR_get_error(), NULL));
			return FALSE;
		}
		int nwritten = fwrite(recorder->ciphertext_buffer, 1, evp_outlen,
				recorder->file);
		if (nwritten < 0) {
			JANUS_LOG(LOG_ERR, "error writing janus log :(\n");
			return FALSE;
		}
	}
	return TRUE;
}

/********************************************************************/

void janus_recorder_init(
    gboolean tempnames,
    const char *extension,
    const char *public_key_filename) {
	JANUS_LOG(LOG_INFO, "Initializing recorder code\n");
	if(tempnames) {
		rec_tempname = TRUE;
		if(extension == NULL) {
			rec_tempext = g_strdup("tmp");
			JANUS_LOG(LOG_INFO, "  -- No extension provided, using default one (tmp)");
		} else {
			rec_tempext = g_strdup(extension);
			JANUS_LOG(LOG_INFO, "  -- Using temporary extension .%s", rec_tempext);
		}
	}
  if (public_key_filename) {
		JANUS_LOG(LOG_INFO, "  -- encrypting recordings with public key: %s\n",
				public_key_filename);
		FILE *pubkey_file = fopen(public_key_filename, "r");
		if (pubkey_file) {
			rec_pubkey = PEM_read_PUBKEY(pubkey_file, NULL, 0, NULL);
			if (rec_pubkey) {
				JANUS_LOG(LOG_INFO, "  -- public key file read successfully\n");
			}
			else {
				JANUS_LOG(LOG_ERR, "  -- error reading public key file %s: %s\n",
						public_key_filename, ERR_error_string(ERR_get_error(), NULL));
			}
		}
		else {
			JANUS_LOG(LOG_ERR, "  -- unable to open public key file: %s\n",
					public_key_filename);
		}
	}
}

void janus_recorder_deinit(void) {
	rec_tempname = FALSE;
	g_free(rec_tempext);
}

static void janus_recorder_free(const janus_refcount *recorder_ref) {
	janus_recorder *recorder = janus_refcount_containerof(recorder_ref, janus_recorder, ref);
	/* This recorder can be destroyed, free all the resources */
	janus_recorder_close(recorder);
	g_free(recorder->dir);
	recorder->dir = NULL;
	g_free(recorder->filename);
	recorder->filename = NULL;
	fclose(recorder->file);
	recorder->file = NULL;
	g_free(recorder->codec);
	recorder->codec = NULL;
	g_free(recorder);
	if (recorder->evp_ctx) {
		EVP_CIPHER_CTX_free(recorder->evp_ctx);
		recorder->evp_ctx = NULL;
	}
	if (recorder->ciphertext_buffer) {
		g_free(recorder->ciphertext_buffer);
		recorder->ciphertext_buffer_len = 0;
	}
}

janus_recorder *janus_recorder_create(const char *dir, const char *codec, const char *filename) {
	janus_recorder_medium type = JANUS_RECORDER_AUDIO;
	if(codec == NULL) {
		JANUS_LOG(LOG_ERR, "Missing codec information\n");
		return NULL;
	}
	if(!strcasecmp(codec, "vp8") || !strcasecmp(codec, "vp9") || !strcasecmp(codec, "h264")) {
		type = JANUS_RECORDER_VIDEO;
	} else if(!strcasecmp(codec, "opus")
			|| !strcasecmp(codec, "g711") || !strcasecmp(codec, "pcmu") || !strcasecmp(codec, "pcma")
			|| !strcasecmp(codec, "g722")) {
		type = JANUS_RECORDER_AUDIO;
	} else if(!strcasecmp(codec, "text")) {
		/* FIXME We only handle text on data channels, so that's the only thing we can save too */
		type = JANUS_RECORDER_DATA;
	} else {
		/* We don't recognize the codec: while we might go on anyway, we'd rather fail instead */
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return NULL;
	}
	/* Create the recorder */
	janus_recorder *rc = g_malloc0(sizeof(janus_recorder));
	rc->dir = NULL;
	rc->filename = NULL;
	rc->file = NULL;
	rc->codec = g_strdup(codec);
	rc->created = janus_get_real_time();
	const char *rec_dir = NULL;
	const char *rec_file = NULL;
	char *copy_for_parent = NULL;
	char *copy_for_base = NULL;
	/* Check dir and filename values */
	if (filename != NULL) {
		/* Helper copies to avoid overwriting */
		copy_for_parent = g_strdup(filename);
		copy_for_base = g_strdup(filename);
		/* Get filename parent folder */
		const char *filename_parent = dirname(copy_for_parent);
		/* Get filename base file */
		const char *filename_base = basename(copy_for_base);
		if (!dir) {
			/* If dir is NULL we have to create filename_parent and filename_base */
			rec_dir = filename_parent;
			rec_file = filename_base;
		} else {
			/* If dir is valid we have to create dir and filename*/
			rec_dir = dir;
			rec_file = filename;
			if (strcasecmp(filename_parent, ".") || strcasecmp(filename_base, filename)) {
				JANUS_LOG(LOG_WARN, "Unsupported combination of dir and filename %s %s\n", dir, filename);
			}
		}
	}
	if(rec_dir != NULL) {
		/* Check if this directory exists, and create it if needed */
		struct stat s;
		int err = stat(rec_dir, &s);
		if(err == -1) {
			if(ENOENT == errno) {
				/* Directory does not exist, try creating it */
				if(janus_mkdir(rec_dir, 0755) < 0) {
					JANUS_LOG(LOG_ERR, "mkdir error: %d\n", errno);
					return NULL;
				}
			} else {
				JANUS_LOG(LOG_ERR, "stat error: %d\n", errno);
				return NULL;
			}
		} else {
			if(S_ISDIR(s.st_mode)) {
				/* Directory exists */
				JANUS_LOG(LOG_VERB, "Directory exists: %s\n", rec_dir);
			} else {
				/* File exists but it's not a directory? */
				JANUS_LOG(LOG_ERR, "Not a directory? %s\n", rec_dir);
				return NULL;
			}
		}
	}
	char newname[1024];
	memset(newname, 0, 1024);
	if(rec_file == NULL) {
		/* Choose a random username */
		if(!rec_tempname) {
			/* Use .mjr as an extension right away */
			g_snprintf(newname, 1024, "janus-recording-%"SCNu32".mjr",
					janus_random_uint32());
		} else {
			/* Append the temporary extension to .mjr, we'll rename when closing */
			g_snprintf(newname, 1024, "janus-recording-%"SCNu32".mjr.%s",
					janus_random_uint32(), rec_tempext);
		}
	} else {
		/* Just append the extension */
		if(!rec_tempname) {
			/* Use .mjr as an extension right away */
			g_snprintf(newname, 1024, "%s.mjr", rec_file);
		} else {
			/* Append the temporary extension to .mjr, we'll rename when closing */
			g_snprintf(newname, 1024, "%s.mjr.%s", rec_file, rec_tempext);
		}
	}
	rc->ciphertext_buffer = NULL;
	rc->ciphertext_buffer_len = 0;
	rc->evp_ctx = NULL;
	if (rec_pubkey) {
		strncat(newname, ".enc", sizeof(newname));
		rc->evp_ctx = EVP_CIPHER_CTX_new();
		if (!rc->evp_ctx) {
			JANUS_LOG(LOG_ERR, "error creating libcrypto context: %s\n",
					ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}
	}
	/* Try opening the file now */
	if(rec_dir == NULL) {
		rc->file = fopen(newname, "wb");
	} else {
		char path[1024];
		memset(path, 0, 1024);
		g_snprintf(path, 1024, "%s/%s", rec_dir, newname);
		rc->file = fopen(path, "wb");
	}
	if(rc->file == NULL) {
		JANUS_LOG(LOG_ERR, "fopen error: %d\n", errno);
		return NULL;
	}
	if(rec_dir)
		rc->dir = g_strdup(rec_dir);
	rc->filename = g_strdup(newname);
	rc->type = type;
  /* if we're encrypting, write the encrypted key and IV first */
	if (rc->evp_ctx) {
		unsigned char iv[16] = {0};
		int len_iv = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
		JANUS_LOG(LOG_INFO, "len_iv = %d\n", len_iv);
		int len_ek = EVP_PKEY_size(rec_pubkey);
		unsigned char encrypted_key[256] = {0};
		unsigned char *encrypted_keys[1] = { &encrypted_key[0] };
		JANUS_LOG(LOG_INFO, "len_ek = %d\n", len_ek);
		int actual_encrypted_key_len = 0;
		int evp_init_rc = EVP_SealInit(rc->evp_ctx, EVP_aes_256_cbc(),
				encrypted_keys, &actual_encrypted_key_len,
				iv, &rec_pubkey, 1);
		JANUS_LOG(LOG_INFO, "EVP_SealInit rc = %d\n", evp_init_rc);
		if (evp_init_rc != 1) {
			JANUS_LOG(LOG_ERR, "OH NO EVP_SealInit rc = %d: %s\n",
					evp_init_rc, ERR_error_string(ERR_get_error(), NULL));
			return NULL;
		}
		if (256 != fwrite(encrypted_key, 1, 256, rc->file)) {
			JANUS_LOG(LOG_ERR, "unable to write encrypted AES key to log file\n");
			return NULL;
		}
		if (16 != fwrite(iv, 1, 16, rc->file)) {
			JANUS_LOG(LOG_ERR, "unable to write AES IV to log file\n");
			return NULL;
		}
  }
	/* Write the first part of the header */
	janus_recorder_write(rc, header, sizeof(header));
	//fwrite(header, sizeof(char), strlen(header), rc->file);
	g_atomic_int_set(&rc->writable, 1);
	/* We still need to also write the info header first */
	g_atomic_int_set(&rc->header, 0);
	janus_mutex_init(&rc->mutex);
	/* Done */
	g_atomic_int_set(&rc->destroyed, 0);
	janus_refcount_init(&rc->ref, janus_recorder_free);
	g_free(copy_for_parent);
	g_free(copy_for_base);
	return rc;
}

int janus_recorder_save_frame(janus_recorder *recorder, char *buffer, uint length) {
	if(!recorder)
		return -1;
	janus_mutex_lock_nodebug(&recorder->mutex);
	if(!buffer || length < 1) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -2;
	}
	if(!recorder->file) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -3;
	}
	if(!g_atomic_int_get(&recorder->writable)) {
		janus_mutex_unlock_nodebug(&recorder->mutex);
		return -4;
	}
	if(!g_atomic_int_get(&recorder->header)) {
		/* Write info header as a JSON formatted info */
		json_t *info = json_object();
		/* FIXME Codecs should be configurable in the future */
		const char *type = NULL;
		if(recorder->type == JANUS_RECORDER_AUDIO)
			type = "a";
		else if(recorder->type == JANUS_RECORDER_VIDEO)
			type = "v";
		else if(recorder->type == JANUS_RECORDER_DATA)
			type = "d";
		json_object_set_new(info, "t", json_string(type));								/* Audio/Video/Data */
		json_object_set_new(info, "c", json_string(recorder->codec));					/* Media codec */
		json_object_set_new(info, "s", json_integer(recorder->created));				/* Created time */
		json_object_set_new(info, "u", json_integer(janus_get_real_time()));			/* First frame written time */
		gchar *info_text = json_dumps(info, JSON_PRESERVE_ORDER);
		json_decref(info);
		uint16_t info_bytes = htons(strlen(info_text));
		janus_recorder_write(recorder, &info_bytes, sizeof(uint16_t));
		//fwrite(&info_bytes, sizeof(uint16_t), 1, recorder->file);
		janus_recorder_write(recorder, info_text, strlen(info_text));
		//fwrite(info_text, sizeof(char), strlen(info_text), recorder->file);
		free(info_text);
		/* Done */
		g_atomic_int_set(&recorder->header, 1);
	}
	/* Write frame header */
	janus_recorder_write(recorder, frame_header, strlen(frame_header));
	//fwrite(frame_header, sizeof(char), strlen(frame_header), recorder->file);
	uint16_t header_bytes = htons(recorder->type == JANUS_RECORDER_DATA ? (length+sizeof(gint64)) : length);
	//fwrite(&header_bytes, sizeof(uint16_t), 1, recorder->file);
	janus_recorder_write(recorder, &header_bytes, sizeof(uint16_t));
	if(recorder->type == JANUS_RECORDER_DATA) {
		/* If it's data, then we need to prepend timing related info, as it's not there by itself */
		gint64 now = htonll(janus_get_real_time());
		janus_recorder_write(recorder, &now, sizeof(gint64));
		//fwrite(&now, sizeof(gint64), 1, recorder->file);
	}
	/* Save packet on file */
	janus_recorder_write(recorder, buffer, length);
	/*
	int temp = 0, tot = length;
	while(tot > 0) {
		temp = fwrite(buffer+length-tot, sizeof(char), tot, recorder->file);
		if(temp <= 0) {
			JANUS_LOG(LOG_ERR, "Error saving frame...\n");
			janus_mutex_unlock_nodebug(&recorder->mutex);
			return -5;
		}
		tot -= temp;
	}
	*/
	/* Done */
	janus_mutex_unlock_nodebug(&recorder->mutex);
	return 0;
}

int janus_recorder_close(janus_recorder *recorder) {
	if(!recorder || !g_atomic_int_compare_and_exchange(&recorder->writable, 1, 0))
		return -1;
	janus_mutex_lock_nodebug(&recorder->mutex);
	if(recorder->file) {
		if (rec_pubkey) {
			unsigned char final_buf[16] = {0};
			int nwritten = 0;
			int rc = EVP_EncryptFinal(recorder->evp_ctx, final_buf, &nwritten);
			JANUS_LOG(LOG_INFO, "EVP_EncryptFinal rc = %d nwritten = %d\n",
					rc, nwritten);
			fwrite(final_buf, 1, nwritten, recorder->file);
		}
		fseek(recorder->file, 0L, SEEK_END);
		size_t fsize = ftell(recorder->file);
		fseek(recorder->file, 0L, SEEK_SET);
		JANUS_LOG(LOG_INFO, "File is %zu bytes: %s\n", fsize, recorder->filename);
	}
	if(rec_tempname) {
		/* We need to rename the file, to remove the temporary extension */
		char newname[1024];
		memset(newname, 0, 1024);
		g_snprintf(newname, strlen(recorder->filename)-strlen(rec_tempext), "%s", recorder->filename);
		char oldpath[1024];
		memset(oldpath, 0, 1024);
		char newpath[1024];
		memset(newpath, 0, 1024);
		if(recorder->dir) {
			g_snprintf(newpath, 1024, "%s/%s", recorder->dir, newname);
			g_snprintf(oldpath, 1024, "%s/%s", recorder->dir, recorder->filename);
		} else {
			g_snprintf(newpath, 1024, "%s", newname);
			g_snprintf(oldpath, 1024, "%s", recorder->filename);
		}
		if(rename(oldpath, newpath) != 0) {
			JANUS_LOG(LOG_ERR, "Error renaming %s to %s...\n", recorder->filename, newname);
		} else {
			JANUS_LOG(LOG_INFO, "Recording renamed: %s\n", newname);
			g_free(recorder->filename);
			recorder->filename = g_strdup(newname);
		}
	}
	janus_mutex_unlock_nodebug(&recorder->mutex);
	return 0;
}

void janus_recorder_destroy(janus_recorder *recorder) {
	if(!recorder || !g_atomic_int_compare_and_exchange(&recorder->destroyed, 0, 1))
		return;
	janus_refcount_decrease(&recorder->ref);
}
