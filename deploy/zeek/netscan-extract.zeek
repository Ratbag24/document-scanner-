##! File extraction for netscan.
##!
##! Carves files out of plaintext traffic and writes them to a directory the
##! netscan watcher polls. Load this from local.zeek:
##!
##!     @load /opt/netscan/deploy/zeek/netscan-extract.zeek
##!
##! Then verify it loaded before trusting it:
##!
##!     zeek -C -r some.pcap /opt/netscan/deploy/zeek/netscan-extract.zeek
##!     ls ./extract_files/
##!
##! Extracted files are named `extract-<source>-<fuid>`, e.g.
##! `extract-HTTP-FQ3rKF1tRJ5XnHhLSc`. The file UID is already unique, so no
##! timestamp is needed; netscan parses the source and UID back out of the name
##! and uses the UID to look the transfer up in files.log.
##!
##! Tune two things before deploying:
##!   * `FileExtract::default_limit` -- the per-file cap. Files larger than this
##!     are TRUNCATED, and a truncated archive scans as corrupt, so set it above
##!     the largest download you care about.
##!   * `skip_mime_types` -- every byte extracted is a byte written to disk.
##!     Streaming video will fill a disk in hours if you do not exclude it.

@load base/files/extract
@load base/frameworks/files

module NetscanExtract;

export {
	## Protocols to extract from. These are the plaintext file-carrying
	## protocols; HTTPS is absent because Zeek cannot see inside it.
	option watch_sources: set[string] = {
		"HTTP",
		"FTP_DATA",
		"SMTP",
		"SMB",
		"IRC_DATA",
		"TFTP",
	};

	## MIME types never worth extracting: large, streamed, and not a delivery
	## vector. Excluding these is what keeps disk use sane.
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
	};
}

# FileExtract::prefix and default_limit are `const &redef`, so they must be set
# with `redef` at parse time -- assigning them inside an event handler is an
# error ("assignment to constant") and the script will not load.
#
# The trailing slash on the prefix is required; without it Zeek prepends the
# value to the filename rather than treating it as a directory.
redef FileExtract::prefix = "/var/log/zeek/extract_files/";
redef FileExtract::default_limit = 64 * 1024 * 1024;

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	# Only files whose transport we care about.
	if ( f$source !in watch_sources )
		return;

	# Skip the bulk media types. A file whose type Zeek could not determine is
	# still extracted -- an unknown type is exactly the interesting case.
	if ( meta?$mime_type && meta$mime_type in skip_mime_types )
		return;

	local fname = fmt("extract-%s-%s", f$source, f$id);

	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
