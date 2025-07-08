all_types = {}
# Web files
web_files = [ '.php5','.xhtml', '.jsbundle','.wasm', '.ts', '.css', '.jsx', '.js', '.vue',  '.html', '.scss', '.php', '.less', '.htm', '.mustache', '.aspx']
all_types['web'] = web_files

system = ['.znb', '.rdl', '.pri', '.ipsw', '.upk', '.woff2', '.3', '.file', '.supported', '.pos', '.regtrans-ms', '.sthlp', '.csl', '.6', '.inf', '.vmt', '.desktop', '.itc', '.foliage', '.deu', '.localstorage-journal', '.cache', '.data', '.cur', '.eot', '.asd', '.mui', '.continuousdata', '.webhistory', '.appcache', '.sqm', '.woff', '.pfm', '.model', '.ttc', '.apmaster', '.xnb', '.simss', '.pssg', '.jrs', '.tm2', '.systemFiles', '.ko', '.1', '.dev', '.vcrd', '.10', '.idx', '.ovl', '.cgs', '.ipmeta', '.glk', '.man', '.0', '.lrprev', '.7', '.aux', '.ds_store', '.thewitchersave', '.sav', '.cat', '.install', '.dmp', '.pxe', '.part', '.shs', '.fnt', '.crash', '.ttf', '.drv', '.raw', '.settingcontent-ms', '.blockdata', '.sys', '.mcdb', '.localstorage', '.stringtable', '.tmp', '.download', '.8', '.lock', '.nif', '.stt', '.acsm', '.4', '.emf', '.civ4savedgame', '.otf', '.bif', '.idrc', '.primitives', '.map', '.blob', '.save', '.9', '.sns', '.apversion', '.adv', '.apdetected', '.atx', '.fon', '.5', '.gpd', '.mot', '.cpl', '.2', '.pac', '.opt', '.etl', '.gadget', '.temp', '.ifi', '.cgz', '.vtf', '.fragment', '.sbstore', '.nib', '.supf', '.supx', '.supp', '.mf', '.car', '.mom', '.modulemap', '.intentdefinition', '.sinf', '.pro', '.kotlin_module', '.kotlin_metadata', '.rsa']
all_types['system'] = system

# Binary files
binary_files = ['', '.obb', ".aar", ".dex",".epk",'.binary','.dylib', '.crx', '.x86', '.csh', '.fish', '.ipa', '.lib', '.class', '.com', '.executableFiles', '.application', '.apk', '.o', '.a', '.msi', '.dll', '.bat', '.pak', '.so', '.bin', '.exe', '.command', '.pbd', '.dmg', '.app', '.jar', '.arm64', '.omo', '.luac', '.swiftdoc', '.net', '.armv7', '.ecm', '.kotlin_builtins', '.kf', '.objectcodec']
all_types['binary'] = binary_files

# Uncompiled code
uncompiled_code = ['.ms', '.lhs', '.devFiles', '.blg', '.kt', '.sublime-snippet', '.pl', '.bas', '.d', '.ads', '.s', '.ftn', '.psd1', '.swift', '.dist', '.sol', '.dsw', '.cpp', '.pp', '.py', '.org%2f2000%2fsvg%22%20width%3d%2232%22', '.vmwarevm',  '.h', '.cxx', '.ps1xml', '.make', '.2.ada', '.go', '.lst', '.cob', '.nas', '.m', '.rss', '.mm', '.zsh', '.lua', '.for', '.hh', '.phps', '.rs', '.java', '.bbl', '.f90', '.vbs', '.makefile', '.ada', '.xcodeproj', '.def', '.jav', '.pyc', '.po', '.swg',  '.rq', '.vb',  '.bash', '.props', '.vim', '.seto', '.cbl', '.e', '.jsonp', '.frm', '.f77', '.rdf', '.f',  '.1.ada', '.dashtoc', '.cc', '.p', '.patch',  '.vbox-prev',  '.asm', '.ashx', '.psm', '.bsh', '.hs', '.c++', '.vs', '.ttl', '.3mf', '.rb', '.myi',  '.mo', '.scala', '.adb', '.up_meta', '.psrc', '.diff', '.jsp',  '.v', '.c#', '.cmake', '.ps1', '.pch', '.fth',  '.obj', '.psm1', '.psd', '.c', '.cs', '.vbox', '.manifest', '.el', '.m4', '.cmd', '.vbscript', '.down_meta', '.vhd', '.lisp', '.nim', '.myd', '.sh',  '.j', '.vcxproj', '.simt', '.hxx', '.options', '.pyo', '.clj', '.groovy', '.hpp', '.ksh', '.xsl', '.tpm']  
all_types['code'] = uncompiled_code


# Config data
config = ['.assets', '.assetbundle','.podspec','.xcent','.plist', ".toml", ".arsc", ".pb", '.config', '.cfg', '.conf', '.ini', '.properties', '.json', '.yaml', '.yml', '.xml', '.bundle', '.proto', ".axml", '.storekit','.strings', '.stringsdict', '.dict', '.xctestplan', '.prop', '.geojson', '.appintentsmanifest', '.bincfg', '.xliff', '.prof', '.profm', '.xcconfig', '.entitlements', '.xsd', '.version']
all_types['config'] = config

# Media
# Video
video = [".avc", ".scc", ".tp",'.avchd', '.swf', '.ogg', '.3gp', '.aaf', '.m4p', '.mpeg', '.ogv', '.mp2', '.ogm', '.srt', '.mp4', '.mpv', '.mng', '.mpe', '.mov', '.webm', '.wmv', '.mxf', '.drc', '.rm', '.roq', '.svi', '.qt', '.nsv', '.mk4', '.avi', '.mpg', '.h264', '.videoFiles', '.trec', '.asf', '.mkv', '.3g2', '.m2v', '.flv', '.m4v', '.yuv', '.vob', '.rmvb']
# Audio
audio = ['.emp', '.pls', '.flac', '.l6t', '.aac', '.dmpatch', '.aif', '.xm', '.midi', '.adx', '.au', '.mp3', '.ape', '.oct', '.ens', '.s3m', '.mpa', '.it', '.pcm', '.m3u', '.cda', '.seq', '.lng', '.mtp', '.link', '.wma', '.m4a', '.gsm', '.wem', '.aiff', '.mod', '.adg', '.sid', '.wav', '.sngw', '.mid', '.audioFiles', '.ra', '.m4r', '.caf', '.flr', '.sf', '.bnk', '.bks']
# Images
images = ['.pngx', '.3ds', '.icon', '.kmz', '.djvu', '.max', '.rds', '.xcf', '.webp', '.thm', '.tif', '.pic', '.gpx', '.img', '.imageFiles', '.cr2', '.3dm', '.jfif', '.icns', '.png0', '.eps', '.ai', '.svg', '.visual', '.dwg', '.png', '.dng', '.psb', '.shape',  '.hdr', '.aae', '.catalog', '.px', '.fla', '.dxf', '.ps', '.heic', '.photoscachefile', '.apalbum', '.jpeg', '.apfolder', '.ithmb', '.gif', '.odg', '.dds', '.bmp', '.ico', '.kml',  '.xmp', '.appicon', '.jpg', '.ita', '.tiff', '.tga', '.metallib']
all_types['video'] = video
all_types['audio'] = audio
all_types['image'] = images

all_types['game'] = ['.level', '.unity3d', '.p2d', '.vert', '.csb', '.mesh', '.ccz', '.vsh', '.fsh', '.sks', '.resource', '.frag', '.cikernel', '.skel', '.u', '.bcmap', '.tmx', '.glsl', '.ress', '.atlas']

# Certificates and keys
certificates_keys = [".pk12", '.pem', '.crt', '.cer', '.key', '.p12', '.pfx', '.pub', '.asc', '.gpg', '.pgp', ".der", '.jks', '.md5']
all_types['cryptography'] = certificates_keys


# Archives
archives = ['.zzip','.lha', '.egg', '.tbz2', '.whl', '.009', '.package', '.xpi', '.arj', '.ova', '.004', '.zip', '.vdi', '.xz', '.pea', '.tgz', '.pkg', '.vmdk', '.z', '.tlz', '.ims', '.008', '.archiveFiles', '.bz2', '.deb', '.mar', '.tar', '.003', '.war', '.rar', '.gz', '.cpio', '.rpm', '.001', '.006', '.vcd', '.005', '.002', '.cab', '.lzma', '.ar', '.7z', '.zipx', '.shar', '.ost', '.iso', '.007', '.s7z', '.glz', '.czl']
all_types['archives'] = archives

# Documents
text = [".markdown", '.opf', '.wps', '.fra', '.utf8', '.txt', '.ebook', '.chm', '.docx', '.docm', '.pdf', '.azw6', '.text', '.cbz', '.wks', '.epub', '.md', '.tex', '.mobi', '.nfo', '.pages', '.rtf', '.azw3', '.msg', '.dvi', '.pfb', '.textFiles', '.doc', '.log2', '.cbr', '.azw1', '.azw', '.abw', '.org', '.azw4', '.log', '.rst', '.odt', '.bib', '.log1', '.ott', '.ichat', '.wpd', '.emlx', '.lic', '.rsp', '.list', '.mdown']
spreadsheet = ['.xlr', '.ics', '.odf', '.xlk', '.vcf', '.ods', '.xlsx', '.spreadsheetFiles', '.csv', '.numbers', '.xls']
presentation = ['.presentationFiles', '.ppt', '.pptx', '.pps', '.ppsx', '.odp']
all_types['text'] = text
all_types['spreadsheet'] = spreadsheet

# Database files
db = ['.graphql', ".database", ".sqlite", '.sdf', '.sqlite-wal', '.appinfo', '.enz', '.accdb', '.gdbtable', '.odb', '.xg0', '.mdb', '.yg0', '.asy', '.r', '.db', '.hdb', '.meta', '.databaseFiles', '.gdbtablx', '.xyz', '.adf', '.gdbindexes', '.mat', '.sql', '.accde', '.sqlite', '.cif', '.bgl', '.info', '.mde', '.cdb', '.enl', '.exp', '.gdb', '.dat', '.data', '.realm', '.pdb','.cdm']
all_types['database'] = db

machine_learning = ['.prototxt', '.pt2', '.prompt', '.mar', '.llamafile', '.ckpt', '.pth', '.ggjt', '.pte', '.mleap', '.gguf', '.caffemodel', '.npy', '.surml', '.tfrecords', '.pkl', '.h5', '.ptl', '.npz', '.keras',  '.onnx', '.nc', '.ggmf', '.tflite', '.dlc', '.safetensors', '.coreml', '.pt', '.ggml', ".mlmodel", ".mlmodelc", ".hdf5", ".conv_model", '.lstm_model', '.weights', '.traineddata', '.emd']
all_types['ai model'] = machine_learning 

# Other categories
backup = ['.backupFiles', '.bak', '.backup', '.back', ".pbf", '.stg']
all_types['backup'] = backup



