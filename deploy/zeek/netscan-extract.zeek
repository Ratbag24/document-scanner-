##! File extraction for netscan.
##!
##! Carves files out of plaintext traffic and writes them to a directory the
##! netscan watcher polls. Load this from local.zeek:
##!
##!     @load /opt/netscan/deploy/zeek/netscan-extract.zeek
##!
##! Tune the two things that matter before deploying:
##!   * `extract_limit` -- the per-file cap. Files larger than this are truncated,
##!     and a truncated archive scans as corrupt, so set it above the largest
##!     download you care about rather than leaving it small.
##!   * `skip_mime_types` -- every byte you extract is a byte written to disk.
##!     Streaming video will fill a disk in hours if you do not exclude it.

@load base/files/extract
@load base/frameworks/files

module NetscanExtract;

export {
	## Where extracted files are written. Must match netscan's
	## `[ingest].zeek_extract_dir`.
	option extract_prefix = "/var/log/zeek/extract_files/" &redef;

	## Per-file extraction cap in bytes. Larger files are truncated.
	option extract_limit = 64 * 1024 * 1024 &redef;

	## MIME types never worth extracting: large, streamed, and not a delivery
	## vector for anything. Excluding these is what keeps disk use sane.
	option skip_mime_types: set[string] = {
		"video/mp4",
		"video/mpeg",
		"video/webm",
		"video/x-flv",
		"video/x-matroska",
		"audio/mpeg",
		"audio/mp4",
		"audio/aac",
		"audio/ogg",
		"application/x-mpegurl",
		"application/vnd.apple.mpegurl",
		"image/gif",
		"font/woff",
		"font/woff2",
	} &redef;

	## Protocols to extract from. Everything else is ignored. These are the
	## plaintext file-carrying protocols; HTTPS is absent because Zeek cannot
	## see inside it (see docs/DEPLOYMENT.md).
	option watch_sources: set[string] = {
		"HTTP",
		"FTP_DATA",
		"SMTP",
		"SMB",
		"IRC_DATA",
		"TFTP",
	} &redef;
}

event zeek_init()
	{
	FileExtract::prefix = extract_prefix;
	FileExtract::default_limit = extract_limit;
	}

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	# Only files whose transport we care about.
	if ( f$source !in watch_sources )
		return;

	# Zeek has not identified a type yet -- extract anyway, since an unknown
	# type is exactly the interesting case, but skip empty files.
	if ( meta?$mime_type && meta$mime_type in skip_mime_types )
		return;

	# Name the file so netscan can tie it back to this transfer:
	#   extract-<timestamp>-<source>-<fuid>
	local fname = fmt("extract-%f-%s-%s", network_time(), f$source, f$id);

	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
	                    [$extract_filename=fname, $extract_limit=extract_limit]);
	}
