'use strict';

var obsidian = require('obsidian');
var crypto = require('crypto');
var http = require('http');
var https = require('https');
var URL = require('url');
var querystring = require('querystring');
var require$$0 = require('buffer');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var crypto__default = /*#__PURE__*/_interopDefaultLegacy(crypto);
var http__default = /*#__PURE__*/_interopDefaultLegacy(http);
var https__default = /*#__PURE__*/_interopDefaultLegacy(https);
var URL__default = /*#__PURE__*/_interopDefaultLegacy(URL);
var querystring__default = /*#__PURE__*/_interopDefaultLegacy(querystring);
var require$$0__default = /*#__PURE__*/_interopDefaultLegacy(require$$0);

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

function createCommonjsModule(fn, basedir, module) {
	return module = {
		path: basedir,
		exports: {},
		require: function (path, base) {
			return commonjsRequire(path, (base === undefined || base === null) ? module.path : base);
		}
	}, fn(module, module.exports), module.exports;
}

function commonjsRequire () {
	throw new Error('Dynamic requires are not currently supported by @rollup/plugin-commonjs');
}

/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS 180-1
 * Version 2.2 Copyright Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */
var b64pad  = "="; /* base-64 pad character. "=" for strict RFC compliance   */
function b64_hmac_sha1(k, d)
  { return rstr2b64(rstr_hmac_sha1(str2rstr_utf8(k), str2rstr_utf8(d))); }

/*
 * Calculate the HMAC-SHA1 of a key and some data (raw strings)
 */
function rstr_hmac_sha1(key, data)
{
  var bkey = rstr2binb(key);
  if(bkey.length > 16) bkey = binb_sha1(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binb_sha1(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
  return binb2rstr(binb_sha1(opad.concat(hash), 512 + 160));
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad; } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Convert a raw string to an array of big-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binb(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
  return output;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (24 - i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the SHA-1 of an array of big-endian words, and a bit length
 */
function binb_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      if(j < 16) w[j] = x[i + j];
      else w[j] = bit_rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      var t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                       safe_add(safe_add(e, w[j]), sha1_kt(j)));
      e = d;
      d = c;
      c = bit_rol(b, 30);
      b = a;
      a = t;
    }

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
    e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

var HMACSHA1= function(key, data) {
  return b64_hmac_sha1(key, data);
};

var sha1 = {
	HMACSHA1: HMACSHA1
};

// Returns true if this is a host that closes *before* it ends?!?!
var isAnEarlyCloseHost= function( hostName ) {
  return hostName && hostName.match(".*google(apis)?.com$")
};

var _utils = {
	isAnEarlyCloseHost: isAnEarlyCloseHost
};

var oauth = createCommonjsModule(function (module, exports) {
exports.OAuth= function(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = false;

  this._requestUrl= requestUrl;
  this._accessUrl= accessUrl;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;
  if( authorize_callback === undefined ) {
    this._authorize_callback= "oob";
  }
  else {
    this._authorize_callback= authorize_callback;
  }

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod )
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._clientOptions= this._defaultClientOptions= {"requestTokenHttpMethod": "POST",
                                                    "accessTokenHttpMethod": "POST",
                                                    "followRedirects": true};
  this._oauthParameterSeperator = ",";
};

exports.OAuthEcho= function(realm, verify_credentials, consumerKey, consumerSecret, version, signatureMethod, nonceSize, customHeaders) {
  this._isEcho = true;

  this._realm= realm;
  this._verifyCredentials = verify_credentials;
  this._consumerKey= consumerKey;
  this._consumerSecret= this._encodeData( consumerSecret );
  if (signatureMethod == "RSA-SHA1") {
    this._privateKey = consumerSecret;
  }
  this._version= version;

  if( signatureMethod != "PLAINTEXT" && signatureMethod != "HMAC-SHA1" && signatureMethod != "RSA-SHA1")
    throw new Error("Un-supported signature method: " + signatureMethod );
  this._signatureMethod= signatureMethod;
  this._nonceSize= nonceSize || 32;
  this._headers= customHeaders || {"Accept" : "*/*",
                                   "Connection" : "close",
                                   "User-Agent" : "Node authentication"};
  this._oauthParameterSeperator = ",";
};

exports.OAuthEcho.prototype = exports.OAuth.prototype;

exports.OAuth.prototype._getTimestamp= function() {
  return Math.floor( (new Date()).getTime() / 1000 );
};

exports.OAuth.prototype._encodeData= function(toEncode){
 if( toEncode == null || toEncode == "" ) return ""
 else {
    var result= encodeURIComponent(toEncode);
    // Fix the mismatch between OAuth's  RFC3986's and Javascript's beliefs in what is right and wrong ;)
    return result.replace(/\!/g, "%21")
                 .replace(/\'/g, "%27")
                 .replace(/\(/g, "%28")
                 .replace(/\)/g, "%29")
                 .replace(/\*/g, "%2A");
 }
};

exports.OAuth.prototype._decodeData= function(toDecode) {
  if( toDecode != null ) {
    toDecode = toDecode.replace(/\+/g, " ");
  }
  return decodeURIComponent( toDecode);
};

exports.OAuth.prototype._getSignature= function(method, url, parameters, tokenSecret) {
  var signatureBase= this._createSignatureBase(method, url, parameters);
  return this._createSignature( signatureBase, tokenSecret );
};

exports.OAuth.prototype._normalizeUrl= function(url) {
  var parsedUrl= URL__default['default'].parse(url, true);
   var port ="";
   if( parsedUrl.port ) {
     if( (parsedUrl.protocol == "http:" && parsedUrl.port != "80" ) ||
         (parsedUrl.protocol == "https:" && parsedUrl.port != "443") ) {
           port= ":" + parsedUrl.port;
         }
   }

  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";

  return parsedUrl.protocol + "//" + parsedUrl.hostname + port + parsedUrl.pathname;
};

// Is the parameter considered an OAuth parameter
exports.OAuth.prototype._isParameterNameAnOAuthParameter= function(parameter) {
  var m = parameter.match('^oauth_');
  if( m && ( m[0] === "oauth_" ) ) {
    return true;
  }
  else {
    return false;
  }
};

// build the OAuth request authorization header
exports.OAuth.prototype._buildAuthorizationHeaders= function(orderedParameters) {
  var authHeader="OAuth ";
  if( this._isEcho ) {
    authHeader += 'realm="' + this._realm + '",';
  }

  for( var i= 0 ; i < orderedParameters.length; i++) {
     // Whilst the all the parameters should be included within the signature, only the oauth_ arguments
     // should appear within the authorization header.
     if( this._isParameterNameAnOAuthParameter(orderedParameters[i][0]) ) {
      authHeader+= "" + this._encodeData(orderedParameters[i][0])+"=\""+ this._encodeData(orderedParameters[i][1])+"\""+ this._oauthParameterSeperator;
     }
  }

  authHeader= authHeader.substring(0, authHeader.length-this._oauthParameterSeperator.length);
  return authHeader;
};

// Takes an object literal that represents the arguments, and returns an array
// of argument/value pairs.
exports.OAuth.prototype._makeArrayOfArgumentsHash= function(argumentsHash) {
  var argument_pairs= [];
  for(var key in argumentsHash ) {
    if (argumentsHash.hasOwnProperty(key)) {
       var value= argumentsHash[key];
       if( Array.isArray(value) ) {
         for(var i=0;i<value.length;i++) {
           argument_pairs[argument_pairs.length]= [key, value[i]];
         }
       }
       else {
         argument_pairs[argument_pairs.length]= [key, value];
       }
    }
  }
  return argument_pairs;
};

// Sorts the encoded key value pairs by encoded name, then encoded value
exports.OAuth.prototype._sortRequestParams= function(argument_pairs) {
  // Sort by name, then value.
  argument_pairs.sort(function(a,b) {
      if ( a[0]== b[0] )  {
        return a[1] < b[1] ? -1 : 1;
      }
      else return a[0] < b[0] ? -1 : 1;
  });

  return argument_pairs;
};

exports.OAuth.prototype._normaliseRequestParams= function(args) {
  var argument_pairs= this._makeArrayOfArgumentsHash(args);
  // First encode them #3.4.1.3.2 .1
  for(var i=0;i<argument_pairs.length;i++) {
    argument_pairs[i][0]= this._encodeData( argument_pairs[i][0] );
    argument_pairs[i][1]= this._encodeData( argument_pairs[i][1] );
  }

  // Then sort them #3.4.1.3.2 .2
  argument_pairs= this._sortRequestParams( argument_pairs );

  // Then concatenate together #3.4.1.3.2 .3 & .4
  var args= "";
  for(var i=0;i<argument_pairs.length;i++) {
      args+= argument_pairs[i][0];
      args+= "=";
      args+= argument_pairs[i][1];
      if( i < argument_pairs.length-1 ) args+= "&";
  }
  return args;
};

exports.OAuth.prototype._createSignatureBase= function(method, url, parameters) {
  url= this._encodeData( this._normalizeUrl(url) );
  parameters= this._encodeData( parameters );
  return method.toUpperCase() + "&" + url + "&" + parameters;
};

exports.OAuth.prototype._createSignature= function(signatureBase, tokenSecret) {
   if( tokenSecret === undefined ) var tokenSecret= "";
   else tokenSecret= this._encodeData( tokenSecret );
   // consumerSecret is already encoded
   var key= this._consumerSecret + "&" + tokenSecret;

   var hash= "";
   if( this._signatureMethod == "PLAINTEXT" ) {
     hash= key;
   }
   else if (this._signatureMethod == "RSA-SHA1") {
     key = this._privateKey || "";
     hash= crypto__default['default'].createSign("RSA-SHA1").update(signatureBase).sign(key, 'base64');
   }
   else {
       if( crypto__default['default'].Hmac ) {
         hash = crypto__default['default'].createHmac("sha1", key).update(signatureBase).digest("base64");
       }
       else {
         hash= sha1.HMACSHA1(key, signatureBase);
       }
   }
   return hash;
};
exports.OAuth.prototype.NONCE_CHARS= ['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
              'o','p','q','r','s','t','u','v','w','x','y','z','A','B',
              'C','D','E','F','G','H','I','J','K','L','M','N','O','P',
              'Q','R','S','T','U','V','W','X','Y','Z','0','1','2','3',
              '4','5','6','7','8','9'];

exports.OAuth.prototype._getNonce= function(nonceSize) {
   var result = [];
   var chars= this.NONCE_CHARS;
   var char_pos;
   var nonce_chars_length= chars.length;

   for (var i = 0; i < nonceSize; i++) {
       char_pos= Math.floor(Math.random() * nonce_chars_length);
       result[i]=  chars[char_pos];
   }
   return result.join('');
};

exports.OAuth.prototype._createClient= function( port, hostname, method, path, headers, sslEnabled ) {
  var options = {
    host: hostname,
    port: port,
    path: path,
    method: method,
    headers: headers
  };
  var httpModel;
  if( sslEnabled ) {
    httpModel= https__default['default'];
  } else {
    httpModel= http__default['default'];
  }
  return httpModel.request(options);
};

exports.OAuth.prototype._prepareParameters= function( oauth_token, oauth_token_secret, method, url, extra_params ) {
  var oauthParameters= {
      "oauth_timestamp":        this._getTimestamp(),
      "oauth_nonce":            this._getNonce(this._nonceSize),
      "oauth_version":          this._version,
      "oauth_signature_method": this._signatureMethod,
      "oauth_consumer_key":     this._consumerKey
  };

  if( oauth_token ) {
    oauthParameters["oauth_token"]= oauth_token;
  }

  var sig;
  if( this._isEcho ) {
    sig = this._getSignature( "GET",  this._verifyCredentials,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }
  else {
    if( extra_params ) {
      for( var key in extra_params ) {
        if (extra_params.hasOwnProperty(key)) oauthParameters[key]= extra_params[key];
      }
    }
    var parsedUrl= URL__default['default'].parse( url, false );

    if( parsedUrl.query ) {
      var key2;
      var extraParameters= querystring__default['default'].parse(parsedUrl.query);
      for(var key in extraParameters ) {
        var value= extraParameters[key];
          if( typeof value == "object" ){
            // TODO: This probably should be recursive
            for(key2 in value){
              oauthParameters[key + "[" + key2 + "]"] = value[key2];
            }
          } else {
            oauthParameters[key]= value;
          }
        }
    }

    sig = this._getSignature( method,  url,  this._normaliseRequestParams(oauthParameters), oauth_token_secret);
  }

  var orderedParameters= this._sortRequestParams( this._makeArrayOfArgumentsHash(oauthParameters) );
  orderedParameters[orderedParameters.length]= ["oauth_signature", sig];
  return orderedParameters;
};

exports.OAuth.prototype._performSecureRequest= function( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type,  callback ) {
  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, extra_params);

  if( !post_content_type ) {
    post_content_type= "application/x-www-form-urlencoded";
  }
  var parsedUrl= URL__default['default'].parse( url, false );
  if( parsedUrl.protocol == "http:" && !parsedUrl.port ) parsedUrl.port= 80;
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) parsedUrl.port= 443;

  var headers= {};
  var authorization = this._buildAuthorizationHeaders(orderedParameters);
  if ( this._isEcho ) {
    headers["X-Verify-Credentials-Authorization"]= authorization;
  }
  else {
    headers["Authorization"]= authorization;
  }

  headers["Host"] = parsedUrl.host;

  for( var key in this._headers ) {
    if (this._headers.hasOwnProperty(key)) {
      headers[key]= this._headers[key];
    }
  }

  // Filter out any passed extra_params that are really to do with OAuth
  for(var key in extra_params) {
    if( this._isParameterNameAnOAuthParameter( key ) ) {
      delete extra_params[key];
    }
  }

  if( (method == "POST" || method == "PUT")  && ( post_body == null && extra_params != null) ) {
    // Fix the mismatch between the output of querystring.stringify() and this._encodeData()
    post_body= querystring__default['default'].stringify(extra_params)
                       .replace(/\!/g, "%21")
                       .replace(/\'/g, "%27")
                       .replace(/\(/g, "%28")
                       .replace(/\)/g, "%29")
                       .replace(/\*/g, "%2A");
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          headers["Content-length"]= post_body.length;
      } else {
          headers["Content-length"]= Buffer.byteLength(post_body);
      }
  } else {
      headers["Content-length"]= 0;
  }

  headers["Content-Type"]= post_content_type;

  var path;
  if( !parsedUrl.pathname  || parsedUrl.pathname == "" ) parsedUrl.pathname ="/";
  if( parsedUrl.query ) path= parsedUrl.pathname + "?"+ parsedUrl.query ;
  else path= parsedUrl.pathname;

  var request;
  if( parsedUrl.protocol == "https:" ) {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers, true);
  }
  else {
    request= this._createClient(parsedUrl.port, parsedUrl.hostname, method, path, headers);
  }

  var clientOptions = this._clientOptions;
  if( callback ) {
    var data="";
    var self= this;

    // Some hosts *cough* google appear to close the connection early / send no content-length header
    // allow this behaviour.
    var allowEarlyClose= _utils.isAnEarlyCloseHost( parsedUrl.hostname );
    var callbackCalled= false;
    var passBackControl = function( response ) {
      if(!callbackCalled) {
        callbackCalled= true;
        if ( response.statusCode >= 200 && response.statusCode <= 299 ) {
          callback(null, data, response);
        } else {
          // Follow 301 or 302 redirects with Location HTTP header
          if((response.statusCode == 301 || response.statusCode == 302) && clientOptions.followRedirects && response.headers && response.headers.location) {
            self._performSecureRequest( oauth_token, oauth_token_secret, method, response.headers.location, extra_params, post_body, post_content_type,  callback);
          }
          else {
            callback({ statusCode: response.statusCode, data: data }, data, response);
          }
        }
      }
    };

    request.on('response', function (response) {
      response.setEncoding('utf8');
      response.on('data', function (chunk) {
        data+=chunk;
      });
      response.on('end', function () {
        passBackControl( response );
      });
      response.on('close', function () {
        if( allowEarlyClose ) {
          passBackControl( response );
        }
      });
    });

    request.on("error", function(err) {
      if(!callbackCalled) {
        callbackCalled= true;
        callback( err );
      }
    });

    if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    request.end();
  }
  else {
    if( (method == "POST" || method =="PUT") && post_body != null && post_body != "" ) {
      request.write(post_body);
    }
    return request;
  }

  return;
};

exports.OAuth.prototype.setClientOptions= function(options) {
  var key,
      mergedOptions= {},
      hasOwnProperty= Object.prototype.hasOwnProperty;

  for( key in this._defaultClientOptions ) {
    if( !hasOwnProperty.call(options, key) ) {
      mergedOptions[key]= this._defaultClientOptions[key];
    } else {
      mergedOptions[key]= options[key];
    }
  }

  this._clientOptions= mergedOptions;
};

exports.OAuth.prototype.getOAuthAccessToken= function(oauth_token, oauth_token_secret, oauth_verifier,  callback) {
  var extraParams= {};
  if( typeof oauth_verifier == "function" ) {
    callback= oauth_verifier;
  } else {
    extraParams.oauth_verifier= oauth_verifier;
  }

   this._performSecureRequest( oauth_token, oauth_token_secret, this._clientOptions.accessTokenHttpMethod, this._accessUrl, extraParams, null, null, function(error, data, response) {
         if( error ) callback(error);
         else {
           var results= querystring__default['default'].parse( data );
           var oauth_access_token= results["oauth_token"];
           delete results["oauth_token"];
           var oauth_access_token_secret= results["oauth_token_secret"];
           delete results["oauth_token_secret"];
           callback(null, oauth_access_token, oauth_access_token_secret, results );
         }
   });
};

// Deprecated
exports.OAuth.prototype.getProtectedResource= function(url, method, oauth_token, oauth_token_secret, callback) {
  this._performSecureRequest( oauth_token, oauth_token_secret, method, url, null, "", null, callback );
};

exports.OAuth.prototype.delete= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "DELETE", url, null, "", null, callback );
};

exports.OAuth.prototype.get= function(url, oauth_token, oauth_token_secret, callback) {
  return this._performSecureRequest( oauth_token, oauth_token_secret, "GET", url, null, "", null, callback );
};

exports.OAuth.prototype._putOrPost= function(method, url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  var extra_params= null;
  if( typeof post_content_type == "function" ) {
    callback= post_content_type;
    post_content_type= null;
  }
  if ( typeof post_body != "string" && !Buffer.isBuffer(post_body) ) {
    post_content_type= "application/x-www-form-urlencoded";
    extra_params= post_body;
    post_body= null;
  }
  return this._performSecureRequest( oauth_token, oauth_token_secret, method, url, extra_params, post_body, post_content_type, callback );
};


exports.OAuth.prototype.put= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("PUT", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
};

exports.OAuth.prototype.post= function(url, oauth_token, oauth_token_secret, post_body, post_content_type, callback) {
  return this._putOrPost("POST", url, oauth_token, oauth_token_secret, post_body, post_content_type, callback);
};

/**
 * Gets a request token from the OAuth provider and passes that information back
 * to the calling code.
 *
 * The callback should expect a function of the following form:
 *
 * function(err, token, token_secret, parsedQueryString) {}
 *
 * This method has optional parameters so can be called in the following 2 ways:
 *
 * 1) Primary use case: Does a basic request with no extra parameters
 *  getOAuthRequestToken( callbackFunction )
 *
 * 2) As above but allows for provision of extra parameters to be sent as part of the query to the server.
 *  getOAuthRequestToken( extraParams, callbackFunction )
 *
 * N.B. This method will HTTP POST verbs by default, if you wish to override this behaviour you will
 * need to provide a requestTokenHttpMethod option when creating the client.
 *
 **/
exports.OAuth.prototype.getOAuthRequestToken= function( extraParams, callback ) {
   if( typeof extraParams == "function" ){
     callback = extraParams;
     extraParams = {};
   }
  // Callbacks are 1.0A related
  if( this._authorize_callback ) {
    extraParams["oauth_callback"]= this._authorize_callback;
  }
  this._performSecureRequest( null, null, this._clientOptions.requestTokenHttpMethod, this._requestUrl, extraParams, null, null, function(error, data, response) {
    if( error ) callback(error);
    else {
      var results= querystring__default['default'].parse(data);

      var oauth_token= results["oauth_token"];
      var oauth_token_secret= results["oauth_token_secret"];
      delete results["oauth_token"];
      delete results["oauth_token_secret"];
      callback(null, oauth_token, oauth_token_secret,  results );
    }
  });
};

exports.OAuth.prototype.signUrl= function(url, oauth_token, oauth_token_secret, method) {

  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  var parsedUrl= URL__default['default'].parse( url, false );

  var query="";
  for( var i= 0 ; i < orderedParameters.length; i++) {
    query+= orderedParameters[i][0]+"="+ this._encodeData(orderedParameters[i][1]) + "&";
  }
  query= query.substring(0, query.length-1);

  return parsedUrl.protocol + "//"+ parsedUrl.host + parsedUrl.pathname + "?" + query;
};

exports.OAuth.prototype.authHeader= function(url, oauth_token, oauth_token_secret, method) {
  if( method === undefined ) {
    var method= "GET";
  }

  var orderedParameters= this._prepareParameters(oauth_token, oauth_token_secret, method, url, {});
  return this._buildAuthorizationHeaders(orderedParameters);
};
});

var oauth2 = createCommonjsModule(function (module, exports) {
exports.OAuth2= function(clientId, clientSecret, baseSite, authorizePath, accessTokenPath, customHeaders) {
  this._clientId= clientId;
  this._clientSecret= clientSecret;
  this._baseSite= baseSite;
  this._authorizeUrl= authorizePath || "/oauth/authorize";
  this._accessTokenUrl= accessTokenPath || "/oauth/access_token";
  this._accessTokenName= "access_token";
  this._authMethod= "Bearer";
  this._customHeaders = customHeaders || {};
  this._useAuthorizationHeaderForGET= false;

  //our agent
  this._agent = undefined;
};

// Allows you to set an agent to use instead of the default HTTP or
// HTTPS agents. Useful when dealing with your own certificates.
exports.OAuth2.prototype.setAgent = function(agent) {
  this._agent = agent;
};

// This 'hack' method is required for sites that don't use
// 'access_token' as the name of the access token (for requests).
// ( http://tools.ietf.org/html/draft-ietf-oauth-v2-16#section-7 )
// it isn't clear what the correct value should be atm, so allowing
// for specific (temporary?) override for now.
exports.OAuth2.prototype.setAccessTokenName= function ( name ) {
  this._accessTokenName= name;
};

// Sets the authorization method for Authorization header.
// e.g. Authorization: Bearer <token>  # "Bearer" is the authorization method.
exports.OAuth2.prototype.setAuthMethod = function ( authMethod ) {
  this._authMethod = authMethod;
};


// If you use the OAuth2 exposed 'get' method (and don't construct your own _request call )
// this will specify whether to use an 'Authorize' header instead of passing the access_token as a query parameter
exports.OAuth2.prototype.useAuthorizationHeaderforGET = function(useIt) {
  this._useAuthorizationHeaderForGET= useIt;
};

exports.OAuth2.prototype._getAccessTokenUrl= function() {
  return this._baseSite + this._accessTokenUrl; /* + "?" + querystring.stringify(params); */
};

// Build the authorization header. In particular, build the part after the colon.
// e.g. Authorization: Bearer <token>  # Build "Bearer <token>"
exports.OAuth2.prototype.buildAuthHeader= function(token) {
  return this._authMethod + ' ' + token;
};

exports.OAuth2.prototype._chooseHttpLibrary= function( parsedUrl ) {
  var http_library= https__default['default'];
  // As this is OAUth2, we *assume* https unless told explicitly otherwise.
  if( parsedUrl.protocol != "https:" ) {
    http_library= http__default['default'];
  }
  return http_library;
};

exports.OAuth2.prototype._request= function(method, url, headers, post_body, access_token, callback) {

  var parsedUrl= URL__default['default'].parse( url, true );
  if( parsedUrl.protocol == "https:" && !parsedUrl.port ) {
    parsedUrl.port= 443;
  }

  var http_library= this._chooseHttpLibrary( parsedUrl );


  var realHeaders= {};
  for( var key in this._customHeaders ) {
    realHeaders[key]= this._customHeaders[key];
  }
  if( headers ) {
    for(var key in headers) {
      realHeaders[key] = headers[key];
    }
  }
  realHeaders['Host']= parsedUrl.host;

  if (!realHeaders['User-Agent']) {
    realHeaders['User-Agent'] = 'Node-oauth';
  }

  if( post_body ) {
      if ( Buffer.isBuffer(post_body) ) {
          realHeaders["Content-Length"]= post_body.length;
      } else {
          realHeaders["Content-Length"]= Buffer.byteLength(post_body);
      }
  } else {
      realHeaders["Content-length"]= 0;
  }

  if( access_token && !('Authorization' in realHeaders)) {
    if( ! parsedUrl.query ) parsedUrl.query= {};
    parsedUrl.query[this._accessTokenName]= access_token;
  }

  var queryStr= querystring__default['default'].stringify(parsedUrl.query);
  if( queryStr ) queryStr=  "?" + queryStr;
  var options = {
    host:parsedUrl.hostname,
    port: parsedUrl.port,
    path: parsedUrl.pathname + queryStr,
    method: method,
    headers: realHeaders
  };

  this._executeRequest( http_library, options, post_body, callback );
};

exports.OAuth2.prototype._executeRequest= function( http_library, options, post_body, callback ) {
  // Some hosts *cough* google appear to close the connection early / send no content-length header
  // allow this behaviour.
  var allowEarlyClose= _utils.isAnEarlyCloseHost(options.host);
  var callbackCalled= false;
  function passBackControl( response, result ) {
    if(!callbackCalled) {
      callbackCalled=true;
      if( !(response.statusCode >= 200 && response.statusCode <= 299) && (response.statusCode != 301) && (response.statusCode != 302) ) {
        callback({ statusCode: response.statusCode, data: result });
      } else {
        callback(null, result, response);
      }
    }
  }

  var result= "";

  //set the agent on the request options
  if (this._agent) {
    options.agent = this._agent;
  }

  var request = http_library.request(options);
  request.on('response', function (response) {
    response.on("data", function (chunk) {
      result+= chunk;
    });
    response.on("close", function (err) {
      if( allowEarlyClose ) {
        passBackControl( response, result );
      }
    });
    response.addListener("end", function () {
      passBackControl( response, result );
    });
  });
  request.on('error', function(e) {
    callbackCalled= true;
    callback(e);
  });

  if( (options.method == 'POST' || options.method == 'PUT') && post_body ) {
     request.write(post_body);
  }
  request.end();
};

exports.OAuth2.prototype.getAuthorizeUrl= function( params ) {
  var params= params || {};
  params['client_id'] = this._clientId;
  return this._baseSite + this._authorizeUrl + "?" + querystring__default['default'].stringify(params);
};

exports.OAuth2.prototype.getOAuthAccessToken= function(code, params, callback) {
  var params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= querystring__default['default'].stringify( params );
  var post_headers= {
       'Content-Type': 'application/x-www-form-urlencoded'
   };


  this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
        // responses should be in JSON
        results= JSON.parse( data );
      }
      catch(e) {
        // .... However both Facebook + Github currently use rev05 of the spec
        // and neither seem to specify a content-type correctly in their response headers :(
        // clients of these services will suffer a *minor* performance cost of the exception
        // being thrown
        results= querystring__default['default'].parse( data );
      }
      var access_token= results["access_token"];
      var refresh_token= results["refresh_token"];
      delete results["refresh_token"];
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
};

// Deprecated
exports.OAuth2.prototype.getProtectedResource= function(url, access_token, callback) {
  this._request("GET", url, {}, "", access_token, callback );
};

exports.OAuth2.prototype.get= function(url, access_token, callback) {
  if( this._useAuthorizationHeaderForGET ) {
    var headers= {'Authorization': this.buildAuthHeader(access_token) };
    access_token= null;
  }
  else {
    headers= {};
  }
  this._request("GET", url, headers, "", access_token, callback );
};
});

var OAuth = oauth.OAuth;
var OAuthEcho = oauth.OAuthEcho;
var OAuth2 = oauth2.OAuth2;

var C__Mapper_Dev_Projects_NoteTweet_node_modules_oauth = {
	OAuth: OAuth,
	OAuthEcho: OAuthEcho,
	OAuth2: OAuth2
};

/**
 * Byte sizes are taken from ECMAScript Language Specification
 * http://www.ecma-international.org/ecma-262/5.1/
 * http://bclary.com/2004/11/07/#a-4.3.16
 */

var byte_size = {
  STRING: 2,
  BOOLEAN: 4,
  NUMBER: 8
};

var Buffer$1 = require$$0__default['default'].Buffer;

function allProperties(obj) {
  const stringProperties = [];
  for (var prop in obj) { 
      stringProperties.push(prop);
  }
  if (Object.getOwnPropertySymbols) {
      var symbolProperties = Object.getOwnPropertySymbols(obj);
      Array.prototype.push.apply(stringProperties, symbolProperties);
  }
  return stringProperties
}

function sizeOfObject (seen, object) {
  if (object == null) {
    return 0
  }

  var bytes = 0;
  var properties = allProperties(object);
  for (var i = 0; i < properties.length; i++) {
    var key = properties[i];
    // Do not recalculate circular references
    if (typeof object[key] === 'object' && object[key] !== null) {
      if (seen.has(object[key])) {
        continue
      }
      seen.add(object[key]);
    }

    bytes += getCalculator(seen)(key);
    try {
      bytes += getCalculator(seen)(object[key]);
    } catch (ex) {
      if (ex instanceof RangeError) {
        // circular reference detected, final result might be incorrect
        // let's be nice and not throw an exception
        bytes = 0;
      }
    }
  }

  return bytes
}

function getCalculator (seen) {
  return function calculator(object) {
    if (Buffer$1.isBuffer(object)) {
      return object.length
    }

    var objectType = typeof (object);
    switch (objectType) {
      case 'string':
        return object.length * byte_size.STRING
      case 'boolean':
        return byte_size.BOOLEAN
      case 'number':
        return byte_size.NUMBER
      case 'symbol':
        const isGlobalSymbol = Symbol.keyFor && Symbol.keyFor(object);
        return isGlobalSymbol ? Symbol.keyFor(object).length * byte_size.STRING : (object.toString().length - 8) * byte_size.STRING 
      case 'object':
        if (Array.isArray(object)) {
          return object.map(getCalculator(seen)).reduce(function (acc, curr) {
            return acc + curr
          }, 0)
        } else {
          return sizeOfObject(seen, object)
        }
      default:
        return 0
    }
  }
}

/**
 * Main module's entry point
 * Calculates Bytes for the provided parameter
 * @param object - handles object/string/boolean/buffer
 * @returns {*}
 */
function sizeof (object) {
  return getCalculator(new WeakSet())(object)
}

var objectSizeof = sizeof;

var utils = createCommonjsModule(function (module, exports) {
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = exports.formatURL = exports.generateHash = exports.createParams = void 0;
exports.createParams = function (params) {
    if (!params) {
        return '';
    }
    var searchParams = new URLSearchParams();
    Object.entries(params).forEach(function (_a) {
        var key = _a[0], value = _a[1];
        if (typeof value === 'boolean') {
            searchParams.append(key, value ? 'true' : 'false');
            return;
        }
        searchParams.append(key, "" + value);
    });
    return "?" + searchParams.toString();
};
exports.generateHash = function (token) {
    var seed = 56852;
    var h1 = 0xdeadbeef ^ seed;
    var h2 = 0x41c6ce57 ^ seed;
    for (var i = 0, ch = void 0; i < token.length; i++) {
        ch = token.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761);
        h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
};
exports.formatURL = function (url) {
    return url
        .replace(/!/g, '%21')
        .replace(/'/g, '%27')
        .replace(/\(/g, '%28')
        .replace(/\)/g, '%29')
        .replace(/\*/g, '%2A');
};
exports.parse = function (body) {
    var parsed = undefined;
    try {
        parsed = JSON.parse(body);
    }
    catch (error) { }
    if (parsed) {
        return parsed;
    }
    try {
        parsed = JSON.parse('{"' + decodeURI(body).replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g, '":"') + '"}');
    }
    catch (error) { }
    if (parsed) {
        return parsed;
    }
    return body;
};
});

var Cache_1 = createCommonjsModule(function (module, exports) {
var __importDefault = (commonjsGlobal && commonjsGlobal.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var object_sizeof_1 = __importDefault(objectSizeof);

var windowSessionStorage = typeof sessionStorage !== 'undefined' ? sessionStorage : undefined;
var Cache = /** @class */ (function () {
    function Cache(ttl, maxByteSize) {
        if (ttl === void 0) { ttl = 360; }
        if (maxByteSize === void 0) { maxByteSize = 16000000; }
        this.cache = new Map();
        this.ttl = ttl;
        this.maxByteSize = maxByteSize;
    }
    Cache.prototype.add = function (query, data) {
        var hashedKey = utils.generateHash(query);
        var added = new Date();
        var entry = {
            added: added,
            data: data,
        };
        this.cache.set(hashedKey, entry);
        windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.setItem(hashedKey, JSON.stringify(entry));
        this.clearSpace();
    };
    Cache.prototype.get = function (query) {
        var hashedKey = utils.generateHash(query);
        if (!this.has(query)) {
            return null;
        }
        try {
            var entry = this.cache.get(hashedKey);
            if (!entry) {
                var sessionData = windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.getItem(hashedKey);
                if (!sessionData) {
                    return;
                }
                return JSON.parse(sessionData);
            }
            return entry.data;
        }
        catch (error) {
            return null;
        }
    };
    Cache.prototype.has = function (query) {
        var hashedKey = utils.generateHash(query);
        try {
            var now = new Date();
            var data = this.cache.get(hashedKey);
            if (!data) {
                var sessionData = windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.getItem(hashedKey);
                if (!sessionData) {
                    return false;
                }
                data = JSON.parse(sessionData);
            }
            var entryAdded = new Date(data.added);
            if (now.getTime() > entryAdded.getTime() + this.ttl * 1000) {
                windowSessionStorage === null || windowSessionStorage === void 0 ? void 0 : windowSessionStorage.removeItem(hashedKey);
                this.cache.delete(hashedKey);
                return false;
            }
            return true;
        }
        catch (error) {
            return false;
        }
    };
    Cache.prototype.clearSpace = function () {
        var cacheArray = Array.from(this.cache);
        if (object_sizeof_1.default(cacheArray) < this.maxByteSize) {
            return;
        }
        cacheArray.sort(function (a, b) { return a[1].added.getTime() - b[1].added.getTime(); });
        var reducedCacheArray = cacheArray.slice(1);
        this.cache = new Map(reducedCacheArray);
        this.clearSpace();
    };
    return Cache;
}());
exports.default = Cache;
});

var Transport_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __rest = (commonjsGlobal && commonjsGlobal.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (commonjsGlobal && commonjsGlobal.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var oauth_1 = __importDefault(C__Mapper_Dev_Projects_NoteTweet_node_modules_oauth);
var Cache_1$1 = __importDefault(Cache_1);

var Transport = /** @class */ (function () {
    function Transport(options) {
        this.credentials = options;
        this.oauth = new oauth_1.default.OAuth('https://api.twitter.com/oauth/request_token', 'https://api.twitter.com/oauth/access_token', this.credentials.apiKey, this.credentials.apiSecret, '1.0A', null, 'HMAC-SHA1');
        if (!(options === null || options === void 0 ? void 0 : options.disableCache)) {
            this.cache = new Cache_1$1.default(options === null || options === void 0 ? void 0 : options.ttl, options.maxByteSize);
        }
    }
    Transport.prototype.updateOptions = function (options) {
        var _this = this;
        options.apiKey; options.apiSecret; var rest = __rest(options, ["apiKey", "apiSecret"]);
        var cleanOptions = rest;
        Object.keys(cleanOptions).forEach(function (key) {
            if (cleanOptions[key]) {
                _this.credentials[key] = cleanOptions[key];
            }
        });
    };
    Transport.prototype.doDeleteRequest = function (url) {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                if (!this.oauth) {
                    throw Error('Unable to make request. Authentication has not been established');
                }
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                            reject(new Error('Unable to make request. Authentication has not been established'));
                            return;
                        }
                        var formattedUrl = utils.formatURL(url);
                        _this.oauth.delete(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, function (err, body) {
                            if (err) {
                                reject(err);
                                return;
                            }
                            if (!body) {
                                resolve({});
                                return;
                            }
                            var result = utils.parse(body.toString());
                            resolve(result);
                        });
                    })];
            });
        });
    };
    Transport.prototype.doGetRequest = function (url) {
        var _a;
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_b) {
                if (!this.oauth) {
                    throw Error('Unable to make request. Authentication has not been established');
                }
                if ((_a = this.cache) === null || _a === void 0 ? void 0 : _a.has(url)) {
                    return [2 /*return*/, this.cache.get(url)];
                }
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                            reject(new Error('Unable to make request. Authentication has not been established'));
                            return;
                        }
                        var formattedUrl = utils.formatURL(url);
                        _this.oauth.get(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, function (err, body) {
                            var _a;
                            if (err) {
                                reject(err);
                                return;
                            }
                            if (!body) {
                                resolve({});
                                return;
                            }
                            var result = utils.parse(body.toString());
                            (_a = _this.cache) === null || _a === void 0 ? void 0 : _a.add(url, result);
                            resolve(result);
                        });
                    })];
            });
        });
    };
    Transport.prototype.doPostRequest = function (url, body, contentType) {
        if (contentType === void 0) { contentType = 'application/x-www-form-urlencoded'; }
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                if (!this.oauth || !this.credentials) {
                    throw Error('Unable to make request. Authentication has not been established');
                }
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        if (!_this.credentials.accessToken || !_this.credentials.accessTokenSecret) {
                            reject(new Error('Unable to make request. Authentication has not been established'));
                            return;
                        }
                        var formattedUrl = utils.formatURL(url);
                        var formattedBody = contentType === 'application/json' ? JSON.stringify(body) : body;
                        _this.oauth.post(formattedUrl, _this.credentials.accessToken, _this.credentials.accessTokenSecret, formattedBody, contentType, function (err, body) {
                            if (err) {
                                reject(err);
                                return;
                            }
                            if (!body) {
                                resolve({});
                                return;
                            }
                            var result = utils.parse(body.toString());
                            resolve(result);
                        });
                    })];
            });
        });
    };
    return Transport;
}());
exports.default = Transport;
});

var BasicsClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var BasicsClient = /** @class */ (function () {
    function BasicsClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Allows a Consumer application to use an OAuth request_token to request user authorization.  This method is a replacement of Section 6.2 of the OAuth 1.0 authentication flow for applications  using the callback authentication flow. The method will use the currently logged in user as the account  for access authorization unless the force_login parameter is set to true.This method differs from  GET oauth / authorize in that if the user has already granted the application permission,  the redirect will occur without the user having to re-approve the application.  To realize this behavior, you must enable the Use Sign in with Twitter setting on your application record.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/authenticate
     * @param parameters
     */
    BasicsClient.prototype.oauthAuthenticate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/oauth/authenticate' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a Consumer application to use an OAuth Request Token to request user authorization.  This method fulfills Section 6.2 of the OAuth 1.0 authentication flow.  Desktop applications must use this method (and cannot use GET oauth / authenticate). Usage Note: An oauth_callback is never sent to this method, provide it to POST oauth / request_token instead.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/authorize
     * @param parameters
     */
    BasicsClient.prototype.oauthAuthorize = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/oauth/authorize' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a Consumer application to exchange the OAuth Request Token for an OAuth Access Token. This method fulfills Section 6.3 of the OAuth 1.0 authentication flow.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/access_token
     * @param parameters
     */
    BasicsClient.prototype.oauthAccessToken = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/oauth/access_token', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a registered application to revoke an issued OAuth access_token  by presenting its client credentials. Once an access_token has been invalidated,  new creation attempts will yield a different Access Token and usage of  the invalidated token will no longer be allowed.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/invalidate_access_token
     * @param parameters
     */
    BasicsClient.prototype.oauthInvalidateToken = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/oauth/invalidate_token', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a registered application to revoke an issued oAuth 2.0 Bearer Token by presenting  its client credentials. Once a Bearer Token has been invalidated, new creation  attempts will yield a different Bearer Token and usage of the invalidated  token will no longer be allowed.Successful responses include a  JSON-structure describing the revoked Bearer Token.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/invalidate_bearer_token
     * @param parameters
     */
    BasicsClient.prototype.oauth2InvalidateToken = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/oauth2/invalidate_token', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a Consumer application to obtain an OAuth Request Token to request user authorization.  This method fulfills Section 6.1 of the OAuth 1.0 authentication flow.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/request_token
     * @param parameters
     */
    BasicsClient.prototype.oauthRequestToken = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/oauth/request_token', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows a registered application to obtain an OAuth 2 Bearer Token,  which can be used to make API requests on an application's own behalf,  without a user context. This is called Application-only authentication. A Bearer Token may be invalidated using oauth2/invalidate_token.  Once a Bearer Token has been invalidated, new creation attempts will yield a different Bearer Token and  usage of the previous token will no longer be allowed. Only one bearer token may exist outstanding for an application, and repeated requests to this method  will yield the same already-existent token until it has been invalidated. Successful responses include a JSON-structure describing the awarded Bearer Token. Tokens received by this method should be cached.  If attempted too frequently, requests will be rejected with a HTTP 403 with code 99.
     *
     * @link https://developer.twitter.com/en/docs/basics/authentication/api-reference/token
     * @param parameters
     */
    BasicsClient.prototype.oauth2Token = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/oauth2/token', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return BasicsClient;
}());
exports.default = BasicsClient;
});

var AccountsAndUsersClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var AccountsAndUsersClient = /** @class */ (function () {
    function AccountsAndUsersClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Returns all lists the authenticating or specified user subscribes to,  including their own. The user is specified using the user_id or screen_name parameters.  If no user is given, the authenticating user is used.A maximum of 100 results will be  returned by this call. Subscribed lists are returned first, followed by owned lists.  This means that if a user subscribes to 90 lists and owns 20 lists, this method returns  90 subscriptions and 10 owned lists. The reverse method returns owned lists first,  so with reverse=true, 20 owned lists and 80 subscriptions would be returned.  If your goal is to obtain every list a user owns or subscribes to,  use GET lists / ownerships and/or GET lists / subscriptions instead.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-list
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsList = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/list.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * members/* Returns the members of the specified list. Private list members will only be shown if the authenticated user owns the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-members
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembers = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/members.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Check if the specified user is a member of the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-members-show
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembersShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/members/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the lists the specified user has been added to.  If user_id or screen_name are not provided,  the memberships for the authenticating user are returned.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-memberships
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMemberships = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/memberships.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the lists owned by the specified Twitter user.  Private lists will only be shown if the authenticated user is also the owner of the lists.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-ownerships
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsOwnerships = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/ownerships.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the specified list. Private lists will only be shown if the authenticated user owns the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-show
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a timeline of tweets authored by members of the specified list.  Retweets are included by default. Use the include_rts=false parameter to omit retweets. Embedded Timelines is a great way to embed list timelines on your website.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-statuses
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsStatuses = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/statuses.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * subscribers/* Returns the subscribers of the specified list.  Private list subscribers will only be shown if the authenticated user owns the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-subscribers
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsSubscribers = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/subscribers.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Check if the specified user is a subscriber of the specified list.  Returns the user if they are a subscriber.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-subscribers-show
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsSubscribersShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/subscribers/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Obtain a collection of the lists the specified user is subscribed to,  20 lists per page by default. Does not include the user's own lists.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/get-lists-subscriptions
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsSubscriptions = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/lists/subscriptions.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Creates a new list for the authenticated user. Note that you can create up to 1000 lists per account.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Deletes the specified list. The authenticated user must own the list to be able to destroy it.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-destroy
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Add a member to a list.  The authenticated user must own the list to be able to add members to it.  Note that lists cannot have more than 5,000 members.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-members-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembersCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/members/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Adds multiple members to a list, by specifying a comma-separated  list of member ids or screen names. The authenticated user must own the  list to be able to add members to it. Note that lists can't have more  than 5,000 members, and you are limited to adding up to 100 members  to a list at a time with this method.Please note that there can be  issues with lists that rapidly remove and add memberships. Take care when  using these methods such that you are not too rapidly switching between  removals and adds on the same list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-members-create_all
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembersCreateAll = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/members/create_all.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Removes the specified member from the list. The authenticated user must be the list's owner to remove members from the list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-members-destroy
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembersDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/members/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Removes multiple members from a list, by specifying a comma-separated list  of member ids or screen names. The authenticated user must own the list to  be able to remove members from it. Note that lists can't have more  than 500 members, and you are limited to removing up to 100 members to a  list at a time with this method.Please note that there can be issues with  lists that rapidly remove and add memberships. Take care when using these methods  such that you are not too rapidly switching between removals and adds on the same list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-members-destroy_all
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsMembersDestroyAll = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/members/destroy_all.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Subscribes the authenticated user to the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-subscribers-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsSubscribersCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/subscribers/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Unsubscribes the authenticated user from the specified list.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-subscribers-destroy
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsSubscribersDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/subscribers/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Updates the specified list. The authenticated user must own the list to be able to update it.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/create-manage-lists/api-reference/post-lists-update
     * @param parameters
     */
    AccountsAndUsersClient.prototype.listsUpdate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/lists/update.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a cursored collection of user IDs for every user following the specified user. At this time, results are ordered with the most recent following first — however,  this ordering is subject to unannounced change and eventual consistency issues. Results are  given in groups of 5,000 user IDs and multiple "pages" of results can be navigated through  using the next_cursor value in subsequent requests. See Using cursors to navigate  collections for more information.This method is especially powerful when used in  conjunction with GET users / lookup, a method that allows  you to convert user IDs into full user objects in bulk.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-followers-ids
     * @param parameters
     */
    AccountsAndUsersClient.prototype.followersIds = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/followers/ids.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a cursored collection of user objects for users following the specified user. At this time, results are ordered with the most recent following first — however,  this ordering is subject to unannounced change and eventual consistency issues.  Results are given in groups of 20 users and multiple "pages" of results can be  navigated through using the next_cursor value in subsequent requests.  See Using cursors to navigate collections for more information.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-followers-list
     * @param parameters
     */
    AccountsAndUsersClient.prototype.followersList = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/followers/list.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a cursored collection of user IDs for every user the specified  user is following (otherwise known as their "friends").At this time, results  are ordered with the most recent following first — however, this ordering  is subject to unannounced change and eventual consistency issues.  Results are given in groups of 5,000 user IDs and multiple "pages"  of results can be navigated through using the next_cursor value in subsequent requests.  See Using cursors to navigate collections for more information.This method is  especially powerful when used in conjunction with GET users / lookup, a method  that allows you to convert user IDs into full user objects in bulk.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friends-ids
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendsIds = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friends/ids.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a cursored collection of user objects for every user the  specified user is following (otherwise known as their "friends").At this time,  results are ordered with the most recent following first — however, this  ordering is subject to unannounced change and eventual consistency issues.  Results are given in groups of 20 users and multiple "pages" of results can  be navigated through using the next_cursor value in subsequent requests.  See Using cursors to navigate collections for more information.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friends-list
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendsList = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friends/list.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of numeric IDs for every user who has a pending request to follow the authenticating user.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friendships-incoming
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsIncoming = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friendships/incoming.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the relationships of the authenticating user to the comma-separated  list of up to 100 screen_names or user_ids provided. Values for connections can be:  following, following_requested, followed_by, none, blocking, muting.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friendships-lookup
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsLookup = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friendships/lookup.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of user_ids that the currently authenticated user does  not want to receive retweets from.Use POST friendships / update to set the  "no retweets" status for a given user account on behalf of the current user.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friendships-no_retweets-ids
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsNoRetweetsIds = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friendships/no_retweets/ids.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of numeric IDs for every protected user for  whom the authenticating user has a pending follow request.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friendships-outgoing
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsOutgoing = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friendships/outgoing.format' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns detailed information about the relationship between two arbitrary users.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-friendships-show
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/friendships/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns fully-hydrated user objects for up to 100 users per request, as specified by comma-separated values passed to the user_id and/or screen_name parameters.This method is especially useful when used in conjunction with collections of user IDs returned from GET friends / ids and GET followers / ids.GET users / show is used to retrieve a single user object.There are a few things to note when using this method. You must be following a protected user to be able to see their most recent status update. If you don't follow a protected user their status will be removed. The order of user IDs or screen names may not match the order of users in the returned array. If a requested user is unknown, suspended, or deleted, then that user will not be returned in the results list. If none of your lookup criteria can be satisfied by returning a user object, a HTTP 404 will be thrown. You are strongly encouraged to use a POST for larger requests.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-users-lookup
     * @param parameters
     */
    AccountsAndUsersClient.prototype.usersLookup = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/users/lookup.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Provides a simple, relevance-based search interface  to public user accounts on Twitter. Try querying by topical interest,  full name, company name, location, or other criteria. Exact match searches  are not supported.Only the first 1,000 matching results are available.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-users-search
     * @param parameters
     */
    AccountsAndUsersClient.prototype.usersSearch = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/users/search.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a variety of information about the user specified by  the required user_id or screen_name parameter.  The author's most recent Tweet will be returned inline when possible.GET users / lookup  is used to retrieve a bulk collection of user objects.You must be following a  protected user to be able to see their most recent Tweet. If you don't follow a  protected user, the user's Tweet will be removed. A Tweet will not always be  returned in the current_status field.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/get-users-show
     * @param parameters
     */
    AccountsAndUsersClient.prototype.usersShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/users/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows the authenticating user to follow (friend) the user  specified in the ID parameter.Returns the followed user when successful.  Returns a string describing the failure condition when unsuccessful.  If the user is already friends with the user a HTTP 403 may be returned,  though for performance reasons this method may also return a HTTP 200 OK  message even if the follow relationship already exists.Actions taken in  this method are asynchronous. Changes will be eventually consistent.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/post-friendships-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/friendships/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Allows the authenticating user to unfollow the user specified  in the ID parameter. Returns the unfollowed user when successful.  Returns a string describing the failure condition when unsuccessful. Actions taken in this method are asynchronous.  Changes will be eventually consistent.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/post-friendships-destroy
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/friendships/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Enable or disable Retweets and device notifications from the specified user.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/follow-search-get-users/api-reference/post-friendships-update
     * @param parameters
     */
    AccountsAndUsersClient.prototype.friendshipsUpdate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/friendships/update.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns settings (including current trend, geo and sleep time information) for the authenticating user.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-account-settings
     */
    AccountsAndUsersClient.prototype.accountSettings = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/account/settings.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns an HTTP 200 OK response code and a representation of the requesting user if authentication was successful; returns a 401 status code and an error message if not. Use this method to test if supplied user credentials are valid.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials
     * @param parameters
     */
    AccountsAndUsersClient.prototype.accountVerifyCredentials = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/account/verify_credentials.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the authenticated user's saved search queries.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-saved_searches-list
     */
    AccountsAndUsersClient.prototype.savedSearchesList = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/saved_searches/list.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Retrieve the information for the saved search represented by the given id. The authenticating user must be the owner of saved search ID being requested.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-saved_searches-show-id
     * @param parameters
     */
    AccountsAndUsersClient.prototype.savedSearchesShowById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/saved_searches/show/' + parameters.id + '.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a map of the available size variations of the specified user's profile banner. If the user has not uploaded a profile banner, a HTTP 404 will be served instead. This method can be used instead of string manipulation on the profile_banner_url returned in user objects as described in Profile Images and Banners. The profile banner data available at each size variant's URL is in PNG format.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/get-users-profile_banner
     * @param parameters
     */
    AccountsAndUsersClient.prototype.usersProfileBanner = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/users/profile_banner.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Removes the uploaded profile banner for the authenticating user. Returns HTTP 200 upon success.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-account-remove_profile_banner
     */
    AccountsAndUsersClient.prototype.accountRemoveProfileBanner = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/account/remove_profile_banner.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Sets some values that users are able to set under the "Account"  tab of their settings page. Only the parameters specified will be updated.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-account-update_profile
     * @param parameters
     */
    AccountsAndUsersClient.prototype.accountUpdateProfile = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/account/update_profile.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Updates the authenticating user's profile background image.  This method can also be used to enable or disable the profile  background image.Although each parameter is marked as optional, at least one of  image or media_id must be provided when making this request.Learn more about the  deprecation of this endpoint via our forum post.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-account-update_profile_background_image
     * @param parameters
     */
    AccountsAndUsersClient.prototype.accountUpdateProfileBackgroundImageRetired = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/account/update_profile_background_image.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Uploads a profile banner on behalf of the authenticating user. More information about sizing variations can be found in User Profile Images and Banners and GET users / profile_banner.Profile banner images are processed asynchronously. The profile_banner_url and its variant sizes will not necessary be available directly after upload.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-account-update_profile_banner
     * @param parameters
     */
    AccountsAndUsersClient.prototype.accountUpdateProfileBanner = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/account/update_profile_banner.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Updates the authenticating user's profile image.  Note that this method expects raw multipart data, not a URL to an image. This method asynchronously processes the uploaded file before updating the  user's profile image URL. You can either update your local cache the next  time you request the user's information, or, at least 5 seconds after  uploading the image, ask for the updated URL using GET users / show.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-account-update_profile_image
     * @param parameters
     */
    AccountsAndUsersClient.prototype.accountUpdateProfileImage = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/account/update_profile_image.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Create a new saved search for the authenticated user. A user may only have 25 saved searches.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-saved_searches-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.savedSearchesCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/saved_searches/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Destroys a saved search for the authenticating user. The authenticating user must be the owner of saved search id being destroyed.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/manage-account-settings/api-reference/post-saved_searches-destroy-id
     * @param parameters
     */
    AccountsAndUsersClient.prototype.savedSearchesDestroyById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/saved_searches/destroy/' + parameters.id + '.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns an array of numeric user ids the authenticating user is blocking. Important This method is cursored, meaning your app must make  multiple requests in order to receive all blocks correctly. See Using cursors to navigate  collections for more details on how cursoring works.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/get-blocks-ids
     */
    AccountsAndUsersClient.prototype.blocksIds = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/blocks/ids.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of user objects that the authenticating user is blocking. Important This method is cursored, meaning your app must make multiple  requests in order to receive all blocks correctly. See Using cursors to  navigate collections for more details on how cursoring works.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/get-blocks-list
     */
    AccountsAndUsersClient.prototype.blocksList = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/blocks/list.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns an array of numeric user ids the authenticating user has muted.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/get-mutes-users-ids
     */
    AccountsAndUsersClient.prototype.mutesUsersIds = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/mutes/users/ids.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns an array of user objects the authenticating user has muted.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/get-mutes-users-list
     */
    AccountsAndUsersClient.prototype.mutesUsersList = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/mutes/users/list.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Blocks the specified user from following the authenticating user.  In addition the blocked user will not show in the authenticating users mentions  or timeline (unless retweeted by another user). If a follow or friend  relationship exists it is destroyed.The URL pattern  /version/block/create/:screen_name_or_user_id.format is still accepted but not  recommended. As a sequence of numbers is a valid screen name we recommend using  the screen_name or user_id parameter instead.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/post-blocks-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.blocksCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/blocks/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Mutes the user specified in the ID parameter for the authenticating user. Returns the muted user when successful. Returns a string describing the  failure condition when unsuccessful.Actions taken in this method are asynchronous.  Changes will be eventually consistent.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/post-mutes-users-create
     * @param parameters
     */
    AccountsAndUsersClient.prototype.mutesUsersCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/mutes/users/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Un-mutes the user specified in the ID parameter for the authenticating user. Returns the unmuted user when successful. Returns a string describing the  failure condition when unsuccessful.Actions taken in this method are asynchronous.  Changes will be eventually consistent.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/post-mutes-users-destroy
     * @param parameters
     */
    AccountsAndUsersClient.prototype.mutesUsersDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/mutes/users/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Report the specified user as a spam account to Twitter.  Additionally, optionally performs the equivalent of POST blocks / create  on behalf of the authenticated user.
     *
     * @link https://developer.twitter.com/en/docs/accounts-and-users/mute-block-report-users/api-reference/post-users-report_spam
     * @param parameters
     */
    AccountsAndUsersClient.prototype.usersReportSpam = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/users/report_spam.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return AccountsAndUsersClient;
}());
exports.default = AccountsAndUsersClient;
});

var TweetsClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var TweetsClient = /** @class */ (function () {
    function TweetsClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Retrieve the identified Collection, presented as a list of the Tweets curated within. The response structure of this method differs significantly from timelines you  may be used to working with elsewhere in the Twitter API.To navigate a Collection,  use the position object of a response, which includes attributes for max_position,  min_position, and was_truncated. was_truncated indicates whether additional  Tweets exist in the collection outside of the range of the current request.  To retrieve Tweets further back in time, use the value of min_position found  in the current response as the max_position parameter in the next call to this endpoint.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/get-collections-entries
     * @param parameters
     */
    TweetsClient.prototype.collectionsEntries = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/collections/entries.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Find Collections created by a specific user or containing a  specific curated Tweet.Results are organized in a cursored collection.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/get-collections-list
     * @param parameters
     */
    TweetsClient.prototype.collectionsList = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/collections/list.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Retrieve information associated with a specific Collection.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/get-collections-show
     * @param parameters
     */
    TweetsClient.prototype.collectionsShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/collections/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Create a Collection owned by the currently authenticated user. The API endpoint may refuse to complete the request if the authenticated  user has exceeded the total number of allowed collections for their account.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-create
     * @param parameters
     */
    TweetsClient.prototype.collectionsCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Permanently delete a Collection owned by the currently authenticated user.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-destroy
     * @param parameters
     */
    TweetsClient.prototype.collectionsDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Add a specified Tweet to a Collection.A collection will store up  to a few thousand Tweets. Adding a Tweet to a collection beyond its  allowed capacity will remove the oldest Tweet in the collection based  on the time it was added to the collection.Use POST collections / entries / curate  to add Tweets to a Collection in bulk.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-entries-add
     * @param parameters
     */
    TweetsClient.prototype.collectionsEntriesAdd = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/entries/add.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Curate a Collection by adding or removing Tweets in bulk.  Updates must be limited to 100 cumulative additions or removals per request. Use POST collections / entries / add and POST collections / entries / remove  to add or remove a single Tweet.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-entries-curate
     */
    TweetsClient.prototype.collectionsEntriesCurate = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/entries/curate.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Move a specified Tweet to a new position in a curation_reverse_chron ordered collection.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-entries-move
     * @param parameters
     */
    TweetsClient.prototype.collectionsEntriesMove = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/entries/move.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Remove the specified Tweet from a Collection.Use POST  collections / entries / curate to remove Tweets from a Collection in bulk.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-entries-remove
     * @param parameters
     */
    TweetsClient.prototype.collectionsEntriesRemove = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/entries/remove.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Update information concerning a Collection owned by the currently authenticated user. Partial updates are not currently supported: please provide name, description,  and url whenever using this method. Omitted description or url parameters will  be treated as if an empty string was passed, overwriting  any previously stored value for the Collection.
     *
     * @link https://developer.twitter.com/en/docs/tweets/curate-a-collection/api-reference/post-collections-update
     * @param parameters
     */
    TweetsClient.prototype.collectionsUpdate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/collections/update.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of the most recent Tweets and Retweets posted  by the authenticating user and the users they follow. The home timeline is  central to how most users interact with the Twitter service.Up to 800  Tweets are obtainable on the home timeline. It is more volatile for  users that follow many users or follow users who Tweet frequently. See Working with Timelines for instructions on traversing timelines efficiently.
     *
     * @link https://developer.twitter.com/en/docs/tweets/timelines/api-reference/get-statuses-home_timeline
     * @param parameters
     */
    TweetsClient.prototype.statusesHomeTimeline = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/home_timeline.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Important notice: On June 19, 2019, we began enforcing a  limit of 100,000 requests per day to the /statuses/mentions_timeline endpoint.  This is in addition to existing user-level rate limits (75 requests / 15-minutes).  This limit is enforced on a per-application basis, meaning that a  single developer app can make up to 100,000 calls during any  single 24-hour period.Returns the 20 most recent mentions  (Tweets containing a users's @screen_name) for the authenticating user. The timeline returned is the equivalent of the one seen when you view  your mentions on twitter.com.This method can only return up to 800 tweets. See Working with Timelines for instructions on traversing timelines.
     *
     * @link https://developer.twitter.com/en/docs/tweets/timelines/api-reference/get-statuses-mentions_timeline
     * @param parameters
     */
    TweetsClient.prototype.statusesMentionsTimeline = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/mentions_timeline.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Important notice: On June 19, 2019, we began enforcing a limit of  100,000 requests per day to the /statuses/user_timeline endpoint,  in addition to existing user-level and app-level rate limits. This limit is applied on a per-application basis, meaning that a single developer app  can make up to 100,000 calls during any single 24-hour period.Returns a collection  of the most recent Tweets posted by the user indicated by the screen_name or  user_id parameters.User timelines belonging to protected users may only be  requested when the authenticated user either "owns" the timeline or is an  approved follower of the owner.The timeline returned is the equivalent of  the one seen as a user's profile on Twitter.This method can only return up  to 3,200 of a user's most recent Tweets. Native retweets of other statuses  by the user is included in this total, regardless of whether include_rts  is set to false when requesting this resource.See Working with Timelines  for instructions on traversing timelines.See Embedded Timelines,  Embedded Tweets, and GET statuses/oembed for tools to render  Tweets according to Display Requirements.
     *
     * @link https://developer.twitter.com/en/docs/tweets/timelines/api-reference/get-statuses-user_timeline
     * @param parameters
     */
    TweetsClient.prototype.statusesUserTimeline = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/user_timeline.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Note: favorites are now known as likes. Returns the 20 most recent Tweets liked by the authenticating or specified user.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-favorites-list
     * @param parameters
     */
    TweetsClient.prototype.favoritesList = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/favorites/list.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns fully-hydrated Tweet objects for up to 100 Tweets per request, as specified by comma-separated values passed to the id parameter.This method is especially useful to get the details (hydrate) a collection of Tweet IDs.GET statuses / show / :id is used to retrieve a single Tweet object.There are a few things to note when using this method. You must be following a protected user to be able to see their most recent Tweets. If you don't follow a protected user their status will be removed. The order of Tweet IDs may not match the order of Tweets in the returned array. If a requested Tweet is unknown or deleted, then that Tweet will not be returned in the results list, unless the map parameter is set to true, in which case it will be returned with a value of null. If none of your lookup criteria matches valid Tweet IDs an empty array will be returned for map=false. You are strongly encouraged to use a POST for larger requests.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-lookup
     * @param parameters
     */
    TweetsClient.prototype.statusesLookup = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/lookup.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of up to 100 user IDs belonging to users who have retweeted the Tweet specified by the id parameter. This method offers similar data to GET statuses / retweets / :id.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-retweeters-ids
     * @param parameters
     */
    TweetsClient.prototype.statusesRetweetersIds = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/retweeters/ids.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of the 100 most recent retweets of the Tweet specified by the id parameter.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-retweets-id
     * @param parameters
     */
    TweetsClient.prototype.statusesRetweetsById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/retweets/' + parameters.id + '.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the most recent Tweets authored by the authenticating user  that have been retweeted by others. This timeline is a subset of the user's GET statuses / user_timeline.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-retweets_of_me
     * @param parameters
     */
    TweetsClient.prototype.statusesRetweetsOfMe = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/retweets_of_me.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a single Tweet, specified by the id parameter. The Tweet's author will also be embedded within the Tweet. See GET statuses / lookup for getting Tweets in bulk (up to 100 per call). See also Embedded Timelines, Embedded Tweets, and GET statuses/oembed for tools to render Tweets according to Display Requirements. About GeoIf there is no geotag for a status, then there will be an  empty <geo></geo> or "geo" : {}.  This can only be populated if the user has used the Geotagging API to send a statuses/update. The JSON response mostly uses conventions laid out in GeoJSON.  The coordinates that Twitter renders are reversed from the GeoJSON specification  (GeoJSON specifies a longitude then a latitude, whereas Twitter represents it as  a latitude then a longitude), eg: "geo":  { "type":"Point", "coordinates":[37.78029, -122.39697] }
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-show-id
     * @param parameters
     */
    TweetsClient.prototype.statusesShowById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/statuses/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Note: favorites are now known as likes.Favorites (likes) the Tweet  specified in the ID parameter as the authenticating user.  Returns the favorite Tweet when successful.The process invoked by  this method is asynchronous. The immediately returned Tweet object may not indicate  the resultant favorited status of the Tweet. A 200 OK response from this method  will indicate whether the intended action was successful or not.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-favorites-create
     * @param parameters
     */
    TweetsClient.prototype.favoritesCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/favorites/create.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Note: favorites are now known as likes.Unfavorites (un-likes) the Tweet  specified in the ID parameter as the authenticating user.  Returns the un-liked Tweet when successful.The process invoked by this method is asynchronous.  The immediately returned Tweet object may not indicate the resultant favorited status of the Tweet.  A 200 OK response from this method will indicate whether the intended action was successful or not.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-favorites-destroy
     * @param parameters
     */
    TweetsClient.prototype.favoritesDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/favorites/destroy.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Destroys the status specified by the required ID parameter. The authenticating user must be the author of the specified status. Returns the destroyed status if successful.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-statuses-destroy-id
     * @param parameters
     */
    TweetsClient.prototype.statusesDestroyById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/statuses/destroy/' + parameters.id + '.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a single Tweet, specified by either a Tweet web URL or the Tweet ID, in an oEmbed-compatible format. The returned HTML snippet will be automatically recognized as an Embedded Tweet when Twitter's widget JavaScript is included on the page. The oEmbed endpoint allows customization of the final appearance of an Embedded Tweet by setting the corresponding properties in HTML markup to b einterpreted by Twitter's JavaScript bundled with the HTML response by default. The format of the returned markup may change over time as Twitter adds new features or adjusts its Tweet representation. The Tweet fallback markup is meant to be cached on your servers for upt o the suggested cache lifetime specified in the cache_age.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/tweets/post-and-engage/api-reference/get-statuses-oembed
     * @param parameters
     */
    TweetsClient.prototype.statusesOembed = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://publish.twitter.com/oembed' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Retweets a tweet. Returns the original Tweet with Retweet details embedded.Usage Notes: This method is subject to update limits. A HTTP 403 will be returned if this limit as been hit. Twitter will ignore attempts to perform duplicate retweets. The retweet_count will be current as of when the payload is generated and may not reflect the exact count. It is intended as an approximation.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-statuses-retweet-id
     * @param parameters
     */
    TweetsClient.prototype.statusesRetweetById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/statuses/retweet/' + parameters.id + '.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Untweets a retweeted status. Returns the original Tweet with Retweet details embedded.Usage Notes: This method is subject to update limits. A HTTP 429 will be returned if this limit has been hit. The untweeted retweet status ID must be authored by the user backing the authentication token. An application must have write privileges to POST. A HTTP 401 will be returned for read-only applications. When passing a source status ID instead of the retweet status ID a HTTP 200 response will be returned with the same Tweet object but no action.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-statuses-unretweet-id
     * @param parameters
     */
    TweetsClient.prototype.statusesUnretweetById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/statuses/unretweet/' + parameters.id + '.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Updates the authenticating user's current status, also known as Tweeting. For each update attempt, the update text is compared with the authenticating  user's recent Tweets. Any attempt that would result in duplication will be  blocked, resulting in a 403 error. A user cannot submit the same status twice in a row. While not rate limited by the API, a user is limited in the number of Tweets they  can create at a time. If the number of updates posted by the user reaches the current  allowed limit this method will return an HTTP 403 error.About Geo Any geo-tagging parameters in the update will be ignored if geo_enabled for the user  is false (this is the default setting for all users, unless the user has enabled geolocation in their settings) The number of digits after the decimal separator passed to lat (up to 8) is tracked so that  when the lat is returned in a status object it will have the same number of digits  after the decimal separator. Use a decimal point as the separator (and not a decimal comma) for the latitude and the longitude  - usage of a decimal comma will cause the geo-tagged portion of the status update to be dropped. For JSON, the response mostly uses conventions described in GeoJSON. However,  the geo object coordinates that Twitter renders are reversed from the GeoJSON specification.  GeoJSON specifies a longitude then a latitude, whereas Twitter represents it as a latitude then  a longitude: "geo": { "type":"Point", "coordinates":[37.78217, -122.40062] } The coordinates object is replacing the geo object (no deprecation date has been set for the geo  object yet) -- the difference is that the coordinates object, in JSON, is now rendered correctly in GeoJSON. If a place_id is passed into the status update, then that place will be attached  to the status. If no place_id was explicitly provided, but latitude and longitude  are, the API attempts to implicitly provide a place by calling geo/reverse_geocode. Users have the ability to remove all geotags from all their Tweets en masse via the  user settings page. Currently there is no method to remove geotags from individual Tweets.
     *
     * @link https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/post-statuses-update
     * @param parameters
     */
    TweetsClient.prototype.statusesUpdate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/statuses/update.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a collection of relevant Tweets matching a specified query. Please note that Twitter's search service and, by extension, the  Search API is not meant to be an exhaustive source of Tweets.  Not all Tweets will be indexed or made available via the search interface. To learn how to use Twitter Search effectively, please see the Standard search  operators page for a list of available filter operators. Also, see the Working with  Timelines page to learn best practices for navigating results by since_id and max_id.
     *
     * @link https://developer.twitter.com/en/docs/tweets/search/api-reference/get-search-tweets
     * @param parameters
     */
    TweetsClient.prototype.search = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/search/tweets.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return TweetsClient;
}());
exports.default = TweetsClient;
});

var DirectMessagesClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var DirectMessagesClient = /** @class */ (function () {
    function DirectMessagesClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Returns a custom profile that was created with POST custom_profiles/new.json.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/custom-profiles/api-reference/get-profile
     * @param parameters
     */
    DirectMessagesClient.prototype.customProfilesById = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/custom_profiles/' + parameters.id + '.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Deletes the direct message specified in the required ID parameter.  The authenticating user must be the recipient of the specified direct message.  Direct Messages are only removed from the interface of the user context provided.  Other members of the conversation can still access the Direct Messages.  A successful delete will return a 204 http response code with no body content. Important: This method requires an access token with RWD  (read, write & direct message) permissions.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/sending-and-receiving/api-reference/delete-message-event
     * @param parameters
     */
    DirectMessagesClient.prototype.eventsDestroy = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doDeleteRequest('https://api.twitter.com/1.1/direct_messages/events/destroy.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a single Direct Message event by the given id.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/sending-and-receiving/api-reference/get-event
     * @param parameters
     */
    DirectMessagesClient.prototype.eventsShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/direct_messages/events/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Publishes a new message_create event resulting in a Direct Message sent to a  specified user from the authenticating user. Returns an event if successful.  Supports publishing Direct Messages with optional Quick Reply and media attachment.  Replaces behavior currently provided by POST direct_messages/new.Requires a  JSON POST body and Content-Type header to be set to application/json.  Setting Content-Length may also be required if it is not automatically.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/sending-and-receiving/api-reference/new-event
     * @param parameters
     */
    DirectMessagesClient.prototype.eventsNew = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/direct_messages/events/new.json', parameters, 'application/json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Displays a visual typing indicator in the recipient’s  Direct Message conversation view with the sender.  Each request triggers a typing indicator animation  with a duration of ~3 seconds.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/typing-indicator-and-read-receipts/api-reference/new-typing-indicator
     * @param parameters
     */
    DirectMessagesClient.prototype.indicateTyping = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/direct_messages/indicate_typing.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a Welcome Message Rule by the given id.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/welcome-messages/api-reference/get-welcome-message-rule
     * @param parameters
     */
    DirectMessagesClient.prototype.welcomeMessagesRulesShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/direct_messages/welcome_messages/rules/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns a Welcome Message by the given id.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/welcome-messages/api-reference/get-welcome-message
     * @param parameters
     */
    DirectMessagesClient.prototype.welcomeMessagesShow = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/direct_messages/welcome_messages/show.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Creates a new Welcome Message that will be stored and sent in the future  from the authenticating user in defined circumstances.  Returns the message template if successful. Supports publishing with the same  elements as Direct Messages (e.g. Quick Replies, media attachments). Requires a JSON POST body and Content-Type header to be set to application/json.  Setting Content-Length may also be required if it is not automatically. See the Welcome Messages overview to learn how to work with Welcome Messages.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/welcome-messages/api-reference/new-welcome-message
     * @param parameters
     */
    DirectMessagesClient.prototype.welcomeMessagesNew = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/direct_messages/welcome_messages/new.json', parameters, 'application/json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Creates a new Welcome Message Rule that determines which Welcome Message will be  shown in a given conversation. Returns the created rule if successful. Requires a JSON POST body and Content-Type header to be set to application/json.  Setting Content-Length may also be required if it is not automatically. Additional rule configurations are forthcoming. For the initial beta release, the most recently created Rule will always take precedence, and the assigned  Welcome Message will be displayed in the conversation.See the Welcome Messages  overview to learn how to work with Welcome Messages.
     *
     * @link https://developer.twitter.com/en/docs/direct-messages/welcome-messages/api-reference/new-welcome-message-rule
     * @param parameters
     */
    DirectMessagesClient.prototype.welcomeMessagesRulesNew = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://api.twitter.com/1.1/direct_messages/welcome_messages/rules/new.json', parameters, 'application/json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return DirectMessagesClient;
}());
exports.default = DirectMessagesClient;
});

var MediaClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var MediaClient = /** @class */ (function () {
    function MediaClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * The INIT command request is used to initiate a file upload session. It returns a media_id which should be used to execute all subsequent requests. The next step after a successful return from INIT command is the APPEND command. See the Uploading media guide for constraints and requirements on media files.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-upload-init
     * @param parameters
     */
    MediaClient.prototype.mediaUploadInit = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/upload.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * The APPEND command is used to upload a chunk (consecutive byte range) of the media file. For example, a 3 MB file could be split into 3 chunks of size 1 MB, and uploaded using 3 APPEND command requests. After the entire file is uploaded, the next step is to call the FINALIZE command.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-upload-append
     * @param parameters
     */
    MediaClient.prototype.mediaUploadAppend = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/upload.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * The STATUS command is used to periodically poll for updates of media processing operation. After the STATUS command response returns succeeded, you can move on to the next step which is usually create Tweet with media_id.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/get-media-upload-status
     * @param parameters
     */
    MediaClient.prototype.mediaUploadStatus = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://upload.twitter.com/1.1/media/upload.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * The FINALIZE command should be called after the entire media file is uploaded using APPEND commands. If and (only if) the response of the FINALIZE command contains a processing_info field, it may also be necessary to use a STATUS command and wait for it to return success before proceeding to Tweet creation.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-upload-finalize
     * @param parameters
     */
    MediaClient.prototype.mediaUploadFinalize = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/upload.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Use this endpoint to upload images to Twitter. This endpoint returns a media_id by default and can optionally return a media_key when a media_category is specified. These values are used by Twitter endpoints that accept images. For example, a media_id value can be used to create a Tweet with an attached photo using the POST statuses/update endpoint. All Ads API endpoints require a media_key. For example, a media_key value can be used to create a Draft Tweet with a photo using the POST accounts/:account_id/draft_tweets endpoint.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-upload
     * @param parameters
     */
    MediaClient.prototype.mediaUpload = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/upload.json', parameters)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * This endpoint can be used to provide additional information about the uploaded media_id. This feature is currently only supported for images and GIFs.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-metadata-create
     * @param parameters
     */
    MediaClient.prototype.mediaMetadataCreate = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/metadata/create.json', parameters, 'application/json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Use this endpoint to dissociate subtitles from a video and delete the subtitles. You can dissociate subtitles from a video before or after Tweeting.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-subtitles-delete
     */
    MediaClient.prototype.mediaSubtitlesDelete = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/subtitles/delete.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Use this endpoint to associate uploaded subtitles to an uploaded video. You can associate subtitles to video before or after Tweeting. Request flow for associating subtitle to video before the video is Tweeted : 1. Upload video using the chunked upload endpoint and get the video media_id. 2. Upload subtitle using the chunked upload endpoint with media category set to “Subtitles” and get the subtitle media_id.  3. Call this endpoint to associate the subtitle to the video. 4. Create Tweet with the video media_id.
     *
     * @link https://developer.twitter.com/en/docs/twitter-api/v1/media/upload-media/api-reference/post-media-subtitles-create
     */
    MediaClient.prototype.mediaSubtitlesCreate = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doPostRequest('https://upload.twitter.com/1.1/media/subtitles/create.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return MediaClient;
}());
exports.default = MediaClient;
});

var TrendsClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var TrendsClient = /** @class */ (function () {
    function TrendsClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Returns the locations that Twitter has trending topic information for.The response is an array of "locations" that encode the location's WOEID and some other human-readable information such as a canonical name and country the location belongs in.A WOEID is a Yahoo! Where On Earth ID.
     *
     * @link https://developer.twitter.com/en/docs/trends/locations-with-trending-topics/api-reference/get-trends-available
     */
    TrendsClient.prototype.trendsAvailable = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/trends/available.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the locations that Twitter has trending topic information for,  closest to a specified location.The response is an array of "locations"  that encode the location's WOEID and some other human-readable information  such as a canonical name and country the location belongs in.A WOEID is a Yahoo!  Where On Earth ID.
     *
     * @link https://developer.twitter.com/en/docs/trends/locations-with-trending-topics/api-reference/get-trends-closest
     * @param parameters
     */
    TrendsClient.prototype.trendsClosest = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/trends/closest.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Returns the top 50 trending topics for a specific WOEID, if trending  information is available for it.The response is an array of trend  objects that encode the name of the trending topic, the query  parameter that can be used to search for the topic on Twitter Search, and the Twitter Search URL.This information is cached for 5 minutes.  Requesting more frequently than that will not return any more data, and  will count against rate limit usage.The tweet_volume for the last 24 hours  is also returned for many trends if this is available.
     *
     * @link https://developer.twitter.com/en/docs/trends/trends-for-location/api-reference/get-trends-place
     * @param parameters
     */
    TrendsClient.prototype.trendsPlace = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/trends/place.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return TrendsClient;
}());
exports.default = TrendsClient;
});

var GeoClient_1 = createCommonjsModule(function (module, exports) {
var __awaiter = (commonjsGlobal && commonjsGlobal.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (commonjsGlobal && commonjsGlobal.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });

var GeoClient = /** @class */ (function () {
    function GeoClient(transport) {
        if (!transport) {
            throw Error('Transport class needs to be provided.');
        }
        this.transport = transport;
    }
    /**
     * Returns all the information about a known place.
     *
     * @link https://developer.twitter.com/en/docs/geo/place-information/api-reference/get-geo-id-place_id
     * @param parameters
     */
    GeoClient.prototype.geoIdByPlaceId = function (parameters) {
        return __awaiter(this, void 0, void 0, function () {
            var params;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        params = utils.createParams(parameters);
                        return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/geo/id/:place_id.json' + params)];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Given a latitude and a longitude, searches for up to 20 places that can be used as a place_id when updating a status.This request is an informative call and will deliver generalized results about geography.
     *
     * @link https://developer.twitter.com/en/docs/geo/places-near-location/api-reference/get-geo-reverse_geocode
     */
    GeoClient.prototype.geoReverseGeocode = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/geo/reverse_geocode.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    /**
     * Search for places that can be attached to a Tweet via POST statuses/update. Given a latitude and a longitude pair, an IP address, or a name, this request will return a list of all the valid places that can be used as the place_id when updating a status.Conceptually, a query can be made from the user's location, retrieve a list of places, have the user validate the location they are at, and then send the ID of this location with a call to POST statuses/update.This is the recommended method to use find places that can be attached to statuses/update. Unlike GET geo/reverse_geocode which provides raw data access, this endpoint can potentially re-order places with regards to the user who is authenticated. This approach is also preferred for interactive place matching with the user.Some parameters in this method are only required based on the existence of other parameters. For instance, "lat" is required if "long" is provided, and vice-versa. Authentication is recommended, but not required with this method.
     *
     * @link https://developer.twitter.com/en/docs/geo/places-near-location/api-reference/get-geo-search
     */
    GeoClient.prototype.geoSearch = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.transport.doGetRequest('https://api.twitter.com/1.1/geo/search.json')];
                    case 1: return [2 /*return*/, _a.sent()];
                }
            });
        });
    };
    return GeoClient;
}());
exports.default = GeoClient;
});

var dist = createCommonjsModule(function (module, exports) {
var __importDefault = (commonjsGlobal && commonjsGlobal.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.TwitterClient = void 0;
var Transport_1$1 = __importDefault(Transport_1);
var BasicsClient_1$1 = __importDefault(BasicsClient_1);
var AccountsAndUsersClient_1$1 = __importDefault(AccountsAndUsersClient_1);
var TweetsClient_1$1 = __importDefault(TweetsClient_1);
var DirectMessagesClient_1$1 = __importDefault(DirectMessagesClient_1);
var MediaClient_1$1 = __importDefault(MediaClient_1);
var TrendsClient_1$1 = __importDefault(TrendsClient_1);
var GeoClient_1$1 = __importDefault(GeoClient_1);
var TwitterClient = /** @class */ (function () {
    /**
     * Provide Twitter API Credentials and options
     * @param options
     */
    function TwitterClient(options) {
        if (!options.apiKey) {
            throw Error('API KEY needs to be provided.');
        }
        if (!options.apiSecret) {
            throw Error('API SECRET needs to be provided.');
        }
        if (!options.accessToken) {
            throw Error('ACCESS TOKEN needs to be provided.');
        }
        if (!options.accessTokenSecret) {
            throw Error('ACCESS TOKEN SECRET needs to be provided.');
        }
        this.transport = new Transport_1$1.default(options);
    }
    Object.defineProperty(TwitterClient.prototype, "basics", {
        get: function () {
            if (!this.basicsClient) {
                this.basicsClient = new BasicsClient_1$1.default(this.transport);
            }
            return this.basicsClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "accountsAndUsers", {
        get: function () {
            if (!this.accountsAndUsersClient) {
                this.accountsAndUsersClient = new AccountsAndUsersClient_1$1.default(this.transport);
            }
            return this.accountsAndUsersClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "tweets", {
        get: function () {
            if (!this.tweetsClient) {
                this.tweetsClient = new TweetsClient_1$1.default(this.transport);
            }
            return this.tweetsClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "directMessages", {
        get: function () {
            if (!this.directMessagesClient) {
                this.directMessagesClient = new DirectMessagesClient_1$1.default(this.transport);
            }
            return this.directMessagesClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "media", {
        get: function () {
            if (!this.mediaClient) {
                this.mediaClient = new MediaClient_1$1.default(this.transport);
            }
            return this.mediaClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "trends", {
        get: function () {
            if (!this.trendsClient) {
                this.trendsClient = new TrendsClient_1$1.default(this.transport);
            }
            return this.trendsClient;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TwitterClient.prototype, "geo", {
        get: function () {
            if (!this.geoClient) {
                this.geoClient = new GeoClient_1$1.default(this.transport);
            }
            return this.geoClient;
        },
        enumerable: false,
        configurable: true
    });
    return TwitterClient;
}());
exports.TwitterClient = TwitterClient;
});

class TwitterHandler {
    constructor() {
        this.isConnectedToTwitter = false;
    }
    connectToTwitter(apiKey, apiSecret, accessToken, accessTokenSecret) {
        try {
            this.twitterClient = new dist.TwitterClient({
                apiKey,
                apiSecret,
                accessToken,
                accessTokenSecret,
            });
            this.isConnectedToTwitter = true;
        }
        catch (e) {
            this.isConnectedToTwitter = false;
        }
    }
    async postThread(threadContent) {
        let postedTweets = [];
        let previousPost;
        for (const tweet of threadContent) {
            let isFirstTweet = threadContent.indexOf(tweet) == 0;
            previousPost = await this.twitterClient.tweets.statusesUpdate(Object.assign({ status: tweet.trim() }, (!isFirstTweet && { in_reply_to_status_id: previousPost.id_str })));
            postedTweets.push(previousPost);
        }
        return postedTweets;
    }
    async postTweet(tweet) {
        return await this.twitterClient.tweets.statusesUpdate({
            status: tweet.trim(),
        });
    }
    async deleteTweets(tweets) {
        try {
            for (const tweet of tweets)
                await this.twitterClient.tweets.statusesDestroyById({
                    id: tweet.id_str,
                });
            return true;
        }
        catch (_a) {
            return false;
        }
    }
}

function noop() { }
function run(fn) {
    return fn();
}
function blank_object() {
    return Object.create(null);
}
function run_all(fns) {
    fns.forEach(run);
}
function is_function(thing) {
    return typeof thing === 'function';
}
function safe_not_equal(a, b) {
    return a != a ? b == b : a !== b || ((a && typeof a === 'object') || typeof a === 'function');
}
function is_empty(obj) {
    return Object.keys(obj).length === 0;
}

function append(target, node) {
    target.appendChild(node);
}
function insert(target, node, anchor) {
    target.insertBefore(node, anchor || null);
}
function detach(node) {
    node.parentNode.removeChild(node);
}
function destroy_each(iterations, detaching) {
    for (let i = 0; i < iterations.length; i += 1) {
        if (iterations[i])
            iterations[i].d(detaching);
    }
}
function element(name) {
    return document.createElement(name);
}
function text(data) {
    return document.createTextNode(data);
}
function space() {
    return text(' ');
}
function listen(node, event, handler, options) {
    node.addEventListener(event, handler, options);
    return () => node.removeEventListener(event, handler, options);
}
function attr(node, attribute, value) {
    if (value == null)
        node.removeAttribute(attribute);
    else if (node.getAttribute(attribute) !== value)
        node.setAttribute(attribute, value);
}
function children(element) {
    return Array.from(element.childNodes);
}
function set_data(text, data) {
    data = '' + data;
    if (text.wholeText !== data)
        text.data = data;
}
function set_input_value(input, value) {
    input.value = value == null ? '' : value;
}
function set_style(node, key, value, important) {
    node.style.setProperty(key, value, important ? 'important' : '');
}

let current_component;
function set_current_component(component) {
    current_component = component;
}

const dirty_components = [];
const binding_callbacks = [];
const render_callbacks = [];
const flush_callbacks = [];
const resolved_promise = Promise.resolve();
let update_scheduled = false;
function schedule_update() {
    if (!update_scheduled) {
        update_scheduled = true;
        resolved_promise.then(flush);
    }
}
function add_render_callback(fn) {
    render_callbacks.push(fn);
}
let flushing = false;
const seen_callbacks = new Set();
function flush() {
    if (flushing)
        return;
    flushing = true;
    do {
        // first, call beforeUpdate functions
        // and update components
        for (let i = 0; i < dirty_components.length; i += 1) {
            const component = dirty_components[i];
            set_current_component(component);
            update(component.$$);
        }
        set_current_component(null);
        dirty_components.length = 0;
        while (binding_callbacks.length)
            binding_callbacks.pop()();
        // then, once components are updated, call
        // afterUpdate functions. This may cause
        // subsequent updates...
        for (let i = 0; i < render_callbacks.length; i += 1) {
            const callback = render_callbacks[i];
            if (!seen_callbacks.has(callback)) {
                // ...so guard against infinite loops
                seen_callbacks.add(callback);
                callback();
            }
        }
        render_callbacks.length = 0;
    } while (dirty_components.length);
    while (flush_callbacks.length) {
        flush_callbacks.pop()();
    }
    update_scheduled = false;
    flushing = false;
    seen_callbacks.clear();
}
function update($$) {
    if ($$.fragment !== null) {
        $$.update();
        run_all($$.before_update);
        const dirty = $$.dirty;
        $$.dirty = [-1];
        $$.fragment && $$.fragment.p($$.ctx, dirty);
        $$.after_update.forEach(add_render_callback);
    }
}
const outroing = new Set();
function transition_in(block, local) {
    if (block && block.i) {
        outroing.delete(block);
        block.i(local);
    }
}
function mount_component(component, target, anchor, customElement) {
    const { fragment, on_mount, on_destroy, after_update } = component.$$;
    fragment && fragment.m(target, anchor);
    if (!customElement) {
        // onMount happens before the initial afterUpdate
        add_render_callback(() => {
            const new_on_destroy = on_mount.map(run).filter(is_function);
            if (on_destroy) {
                on_destroy.push(...new_on_destroy);
            }
            else {
                // Edge case - component was destroyed immediately,
                // most likely as a result of a binding initialising
                run_all(new_on_destroy);
            }
            component.$$.on_mount = [];
        });
    }
    after_update.forEach(add_render_callback);
}
function destroy_component(component, detaching) {
    const $$ = component.$$;
    if ($$.fragment !== null) {
        run_all($$.on_destroy);
        $$.fragment && $$.fragment.d(detaching);
        // TODO null out other refs, including component.$$ (but need to
        // preserve final state?)
        $$.on_destroy = $$.fragment = null;
        $$.ctx = [];
    }
}
function make_dirty(component, i) {
    if (component.$$.dirty[0] === -1) {
        dirty_components.push(component);
        schedule_update();
        component.$$.dirty.fill(0);
    }
    component.$$.dirty[(i / 31) | 0] |= (1 << (i % 31));
}
function init(component, options, instance, create_fragment, not_equal, props, dirty = [-1]) {
    const parent_component = current_component;
    set_current_component(component);
    const $$ = component.$$ = {
        fragment: null,
        ctx: null,
        // state
        props,
        update: noop,
        not_equal,
        bound: blank_object(),
        // lifecycle
        on_mount: [],
        on_destroy: [],
        on_disconnect: [],
        before_update: [],
        after_update: [],
        context: new Map(parent_component ? parent_component.$$.context : options.context || []),
        // everything else
        callbacks: blank_object(),
        dirty,
        skip_bound: false
    };
    let ready = false;
    $$.ctx = instance
        ? instance(component, options.props || {}, (i, ret, ...rest) => {
            const value = rest.length ? rest[0] : ret;
            if ($$.ctx && not_equal($$.ctx[i], $$.ctx[i] = value)) {
                if (!$$.skip_bound && $$.bound[i])
                    $$.bound[i](value);
                if (ready)
                    make_dirty(component, i);
            }
            return ret;
        })
        : [];
    $$.update();
    ready = true;
    run_all($$.before_update);
    // `false` as a special case of no DOM component
    $$.fragment = create_fragment ? create_fragment($$.ctx) : false;
    if (options.target) {
        if (options.hydrate) {
            const nodes = children(options.target);
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            $$.fragment && $$.fragment.l(nodes);
            nodes.forEach(detach);
        }
        else {
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            $$.fragment && $$.fragment.c();
        }
        if (options.intro)
            transition_in(component.$$.fragment);
        mount_component(component, options.target, options.anchor, options.customElement);
        flush();
    }
    set_current_component(parent_component);
}
/**
 * Base class for Svelte components. Used when dev=false.
 */
class SvelteComponent {
    $destroy() {
        destroy_component(this, 1);
        this.$destroy = noop;
    }
    $on(type, callback) {
        const callbacks = (this.$$.callbacks[type] || (this.$$.callbacks[type] = []));
        callbacks.push(callback);
        return () => {
            const index = callbacks.indexOf(callback);
            if (index !== -1)
                callbacks.splice(index, 1);
        };
    }
    $set($$props) {
        if (this.$$set && !is_empty($$props)) {
            this.$$.skip_bound = true;
            this.$$set($$props);
            this.$$.skip_bound = false;
        }
    }
}

/* src\Modals\TweetsPostedModal\TweetsPostedModalContent.svelte generated by Svelte v3.37.0 */

function get_each_context(ctx, list, i) {
	const child_ctx = ctx.slice();
	child_ctx[4] = list[i];
	return child_ctx;
}

// (11:4) {:else}
function create_else_block(ctx) {
	let h2;

	return {
		c() {
			h2 = element("h2");
			h2.textContent = "Your tweet is live! Check it out here:";
		},
		m(target, anchor) {
			insert(target, h2, anchor);
		},
		d(detaching) {
			if (detaching) detach(h2);
		}
	};
}

// (9:4) {#if multiplePosts}
function create_if_block(ctx) {
	let h2;

	return {
		c() {
			h2 = element("h2");
			h2.textContent = "Your tweets are live! Check them out here:";
		},
		m(target, anchor) {
			insert(target, h2, anchor);
		},
		d(detaching) {
			if (detaching) detach(h2);
		}
	};
}

// (15:4) {#each posts as post}
function create_each_block(ctx) {
	let a;
	let t0_value = /*post*/ ctx[4].text + "";
	let t0;
	let a_href_value;
	let t1;
	let br;

	return {
		c() {
			a = element("a");
			t0 = text(t0_value);
			t1 = space();
			br = element("br");
			attr(a, "href", a_href_value = "https://twitter.com/" + /*post*/ ctx[4].user.screen_name + "/status/" + /*post*/ ctx[4].id_str);
		},
		m(target, anchor) {
			insert(target, a, anchor);
			append(a, t0);
			insert(target, t1, anchor);
			insert(target, br, anchor);
		},
		p(ctx, dirty) {
			if (dirty & /*posts*/ 1 && t0_value !== (t0_value = /*post*/ ctx[4].text + "")) set_data(t0, t0_value);

			if (dirty & /*posts*/ 1 && a_href_value !== (a_href_value = "https://twitter.com/" + /*post*/ ctx[4].user.screen_name + "/status/" + /*post*/ ctx[4].id_str)) {
				attr(a, "href", a_href_value);
			}
		},
		d(detaching) {
			if (detaching) detach(a);
			if (detaching) detach(t1);
			if (detaching) detach(br);
		}
	};
}

function create_fragment$2(ctx) {
	let div;
	let t0;
	let t1;
	let button0;
	let t3;
	let button1;
	let mounted;
	let dispose;

	function select_block_type(ctx, dirty) {
		if (/*multiplePosts*/ ctx[3]) return create_if_block;
		return create_else_block;
	}

	let current_block_type = select_block_type(ctx);
	let if_block = current_block_type(ctx);
	let each_value = /*posts*/ ctx[0];
	let each_blocks = [];

	for (let i = 0; i < each_value.length; i += 1) {
		each_blocks[i] = create_each_block(get_each_context(ctx, each_value, i));
	}

	return {
		c() {
			div = element("div");
			if_block.c();
			t0 = space();

			for (let i = 0; i < each_blocks.length; i += 1) {
				each_blocks[i].c();
			}

			t1 = space();
			button0 = element("button");
			button0.textContent = "Great!";
			t3 = space();
			button1 = element("button");
			button1.textContent = "Delete";
			attr(button0, "class", "greenSuccessButton");
			set_style(button0, "float", "right");
			set_style(button0, "margin-top", "1rem");
			attr(button1, "class", "redWarningButton");
			set_style(button1, "float", "right");
			set_style(button1, "margin", "1rem");
		},
		m(target, anchor) {
			insert(target, div, anchor);
			if_block.m(div, null);
			append(div, t0);

			for (let i = 0; i < each_blocks.length; i += 1) {
				each_blocks[i].m(div, null);
			}

			append(div, t1);
			append(div, button0);
			append(div, t3);
			append(div, button1);

			if (!mounted) {
				dispose = [
					listen(button0, "click", function () {
						if (is_function(/*onAccept*/ ctx[2]())) /*onAccept*/ ctx[2]().apply(this, arguments);
					}),
					listen(button1, "click", function () {
						if (is_function(/*onDelete*/ ctx[1]())) /*onDelete*/ ctx[1]().apply(this, arguments);
					})
				];

				mounted = true;
			}
		},
		p(new_ctx, [dirty]) {
			ctx = new_ctx;

			if (dirty & /*posts*/ 1) {
				each_value = /*posts*/ ctx[0];
				let i;

				for (i = 0; i < each_value.length; i += 1) {
					const child_ctx = get_each_context(ctx, each_value, i);

					if (each_blocks[i]) {
						each_blocks[i].p(child_ctx, dirty);
					} else {
						each_blocks[i] = create_each_block(child_ctx);
						each_blocks[i].c();
						each_blocks[i].m(div, t1);
					}
				}

				for (; i < each_blocks.length; i += 1) {
					each_blocks[i].d(1);
				}

				each_blocks.length = each_value.length;
			}
		},
		i: noop,
		o: noop,
		d(detaching) {
			if (detaching) detach(div);
			if_block.d();
			destroy_each(each_blocks, detaching);
			mounted = false;
			run_all(dispose);
		}
	};
}

function instance$2($$self, $$props, $$invalidate) {
	
	let { posts } = $$props;
	let { onDelete } = $$props;
	let { onAccept } = $$props;
	let multiplePosts = posts.length > 1;

	$$self.$$set = $$props => {
		if ("posts" in $$props) $$invalidate(0, posts = $$props.posts);
		if ("onDelete" in $$props) $$invalidate(1, onDelete = $$props.onDelete);
		if ("onAccept" in $$props) $$invalidate(2, onAccept = $$props.onAccept);
	};

	return [posts, onDelete, onAccept, multiplePosts];
}

class TweetsPostedModalContent extends SvelteComponent {
	constructor(options) {
		super();
		init(this, options, instance$2, create_fragment$2, safe_not_equal, { posts: 0, onDelete: 1, onAccept: 2 });
	}
}

class TweetsPostedModal extends obsidian.Modal {
    constructor(app, post, twitterHandler) {
        super(app);
        this.userDeletedTweets = false;
        this.posts = post;
        this.twitterHandler = twitterHandler;
        this.waitForClose = new Promise((resolve) => (this.resolvePromise = resolve));
        this.modalContent = new TweetsPostedModalContent({
            target: this.contentEl,
            props: {
                posts: this.posts,
                onDelete: this.deleteTweets(),
                onAccept: () => this.close(),
            },
        });
        this.open();
    }
    deleteTweets() {
        return async () => {
            let didDeleteTweets = await this.twitterHandler.deleteTweets(this.posts);
            if (didDeleteTweets) {
                this.userDeletedTweets = true;
                this.close();
                new obsidian.Notice(`${this.posts.length} tweet${this.posts.length > 1 ? "s" : ""} deleted.`);
            }
            else
                new obsidian.Notice(`Could not delete tweet(s)`);
        };
    }
    onClose() {
        super.onClose();
        this.modalContent.$destroy();
        this.resolvePromise();
    }
}

class TweetErrorModal extends obsidian.Modal {
    constructor(app, errorMessage) {
        super(app);
        this.errorMessage = errorMessage;
    }
    onOpen() {
        let { contentEl } = this;
        contentEl.setText(`Post failed: ${this.errorMessage}`);
    }
    onClose() {
        let { contentEl } = this;
        contentEl.empty();
    }
}

/* eslint-disable no-use-before-define */

/**
 * Base class for inheritance.
 */
class Base {
  /**
   * Extends this object and runs the init method.
   * Arguments to create() will be passed to init().
   *
   * @return {Object} The new object.
   *
   * @static
   *
   * @example
   *
   *     var instance = MyType.create();
   */
  static create(...args) {
    return new this(...args);
  }

  /**
   * Copies properties into this object.
   *
   * @param {Object} properties The properties to mix in.
   *
   * @example
   *
   *     MyType.mixIn({
   *         field: 'value'
   *     });
   */
  mixIn(properties) {
    return Object.assign(this, properties);
  }

  /**
   * Creates a copy of this object.
   *
   * @return {Object} The clone.
   *
   * @example
   *
   *     var clone = instance.clone();
   */
  clone() {
    const clone = new this.constructor();
    Object.assign(clone, this);
    return clone;
  }
}

/**
 * An array of 32-bit words.
 *
 * @property {Array} words The array of 32-bit words.
 * @property {number} sigBytes The number of significant bytes in this word array.
 */
class WordArray extends Base {
  /**
   * Initializes a newly created word array.
   *
   * @param {Array} words (Optional) An array of 32-bit words.
   * @param {number} sigBytes (Optional) The number of significant bytes in the words.
   *
   * @example
   *
   *     var wordArray = CryptoJS.lib.WordArray.create();
   *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
   *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
   */
  constructor(words = [], sigBytes = words.length * 4) {
    super();

    let typedArray = words;
    // Convert buffers to uint8
    if (typedArray instanceof ArrayBuffer) {
      typedArray = new Uint8Array(typedArray);
    }

    // Convert other array views to uint8
    if (
      typedArray instanceof Int8Array
      || typedArray instanceof Uint8ClampedArray
      || typedArray instanceof Int16Array
      || typedArray instanceof Uint16Array
      || typedArray instanceof Int32Array
      || typedArray instanceof Uint32Array
      || typedArray instanceof Float32Array
      || typedArray instanceof Float64Array
    ) {
      typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
    }

    // Handle Uint8Array
    if (typedArray instanceof Uint8Array) {
      // Shortcut
      const typedArrayByteLength = typedArray.byteLength;

      // Extract bytes
      const _words = [];
      for (let i = 0; i < typedArrayByteLength; i += 1) {
        _words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
      }

      // Initialize this word array
      this.words = _words;
      this.sigBytes = typedArrayByteLength;
    } else {
      // Else call normal init
      this.words = words;
      this.sigBytes = sigBytes;
    }
  }

  /**
   * Creates a word array filled with random bytes.
   *
   * @param {number} nBytes The number of random bytes to generate.
   *
   * @return {WordArray} The random word array.
   *
   * @static
   *
   * @example
   *
   *     var wordArray = CryptoJS.lib.WordArray.random(16);
   */
  static random(nBytes) {
    const words = [];

    const r = (m_w) => {
      let _m_w = m_w;
      let _m_z = 0x3ade68b1;
      const mask = 0xffffffff;

      return () => {
        _m_z = (0x9069 * (_m_z & 0xFFFF) + (_m_z >> 0x10)) & mask;
        _m_w = (0x4650 * (_m_w & 0xFFFF) + (_m_w >> 0x10)) & mask;
        let result = ((_m_z << 0x10) + _m_w) & mask;
        result /= 0x100000000;
        result += 0.5;
        return result * (Math.random() > 0.5 ? 1 : -1);
      };
    };

    for (let i = 0, rcache; i < nBytes; i += 4) {
      const _r = r((rcache || Math.random()) * 0x100000000);

      rcache = _r() * 0x3ade67b7;
      words.push((_r() * 0x100000000) | 0);
    }

    return new WordArray(words, nBytes);
  }

  /**
   * Converts this word array to a string.
   *
   * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
   *
   * @return {string} The stringified word array.
   *
   * @example
   *
   *     var string = wordArray + '';
   *     var string = wordArray.toString();
   *     var string = wordArray.toString(CryptoJS.enc.Utf8);
   */
  toString(encoder = Hex) {
    return encoder.stringify(this);
  }

  /**
   * Concatenates a word array to this word array.
   *
   * @param {WordArray} wordArray The word array to append.
   *
   * @return {WordArray} This word array.
   *
   * @example
   *
   *     wordArray1.concat(wordArray2);
   */
  concat(wordArray) {
    // Shortcuts
    const thisWords = this.words;
    const thatWords = wordArray.words;
    const thisSigBytes = this.sigBytes;
    const thatSigBytes = wordArray.sigBytes;

    // Clamp excess bits
    this.clamp();

    // Concat
    if (thisSigBytes % 4) {
      // Copy one byte at a time
      for (let i = 0; i < thatSigBytes; i += 1) {
        const thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
      }
    } else {
      // Copy one word at a time
      for (let i = 0; i < thatSigBytes; i += 4) {
        thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
      }
    }
    this.sigBytes += thatSigBytes;

    // Chainable
    return this;
  }

  /**
   * Removes insignificant bits.
   *
   * @example
   *
   *     wordArray.clamp();
   */
  clamp() {
    // Shortcuts
    const { words, sigBytes } = this;

    // Clamp
    words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
    words.length = Math.ceil(sigBytes / 4);
  }

  /**
   * Creates a copy of this word array.
   *
   * @return {WordArray} The clone.
   *
   * @example
   *
   *     var clone = wordArray.clone();
   */
  clone() {
    const clone = super.clone.call(this);
    clone.words = this.words.slice(0);

    return clone;
  }
}

/**
 * Hex encoding strategy.
 */
const Hex = {
  /**
   * Converts a word array to a hex string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The hex string.
   *
   * @static
   *
   * @example
   *
   *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
   */
  stringify(wordArray) {
    // Shortcuts
    const { words, sigBytes } = wordArray;

    // Convert
    const hexChars = [];
    for (let i = 0; i < sigBytes; i += 1) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      hexChars.push((bite >>> 4).toString(16));
      hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
  },

  /**
   * Converts a hex string to a word array.
   *
   * @param {string} hexStr The hex string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
   */
  parse(hexStr) {
    // Shortcut
    const hexStrLength = hexStr.length;

    // Convert
    const words = [];
    for (let i = 0; i < hexStrLength; i += 2) {
      words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
    }

    return new WordArray(words, hexStrLength / 2);
  },
};

/**
 * Latin1 encoding strategy.
 */
const Latin1 = {
  /**
   * Converts a word array to a Latin1 string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The Latin1 string.
   *
   * @static
   *
   * @example
   *
   *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
   */
  stringify(wordArray) {
    // Shortcuts
    const { words, sigBytes } = wordArray;

    // Convert
    const latin1Chars = [];
    for (let i = 0; i < sigBytes; i += 1) {
      const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      latin1Chars.push(String.fromCharCode(bite));
    }

    return latin1Chars.join('');
  },

  /**
   * Converts a Latin1 string to a word array.
   *
   * @param {string} latin1Str The Latin1 string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
   */
  parse(latin1Str) {
    // Shortcut
    const latin1StrLength = latin1Str.length;

    // Convert
    const words = [];
    for (let i = 0; i < latin1StrLength; i += 1) {
      words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }

    return new WordArray(words, latin1StrLength);
  },
};

/**
 * UTF-8 encoding strategy.
 */
const Utf8 = {
  /**
   * Converts a word array to a UTF-8 string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The UTF-8 string.
   *
   * @static
   *
   * @example
   *
   *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
   */
  stringify(wordArray) {
    try {
      return decodeURIComponent(escape(Latin1.stringify(wordArray)));
    } catch (e) {
      throw new Error('Malformed UTF-8 data');
    }
  },

  /**
   * Converts a UTF-8 string to a word array.
   *
   * @param {string} utf8Str The UTF-8 string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
   */
  parse(utf8Str) {
    return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
  },
};

/**
 * Abstract buffered block algorithm template.
 *
 * The property blockSize must be implemented in a concrete subtype.
 *
 * @property {number} _minBufferSize
 *
 *     The number of blocks that should be kept unprocessed in the buffer. Default: 0
 */
class BufferedBlockAlgorithm extends Base {
  constructor() {
    super();
    this._minBufferSize = 0;
  }

  /**
   * Resets this block algorithm's data buffer to its initial state.
   *
   * @example
   *
   *     bufferedBlockAlgorithm.reset();
   */
  reset() {
    // Initial values
    this._data = new WordArray();
    this._nDataBytes = 0;
  }

  /**
   * Adds new data to this block algorithm's buffer.
   *
   * @param {WordArray|string} data
   *
   *     The data to append. Strings are converted to a WordArray using UTF-8.
   *
   * @example
   *
   *     bufferedBlockAlgorithm._append('data');
   *     bufferedBlockAlgorithm._append(wordArray);
   */
  _append(data) {
    let m_data = data;

    // Convert string to WordArray, else assume WordArray already
    if (typeof m_data === 'string') {
      m_data = Utf8.parse(m_data);
    }

    // Append
    this._data.concat(m_data);
    this._nDataBytes += m_data.sigBytes;
  }

  /**
   * Processes available data blocks.
   *
   * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
   *
   * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
   *
   * @return {WordArray} The processed data.
   *
   * @example
   *
   *     var processedData = bufferedBlockAlgorithm._process();
   *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
   */
  _process(doFlush) {
    let processedWords;

    // Shortcuts
    const { _data: data, blockSize } = this;
    const dataWords = data.words;
    const dataSigBytes = data.sigBytes;
    const blockSizeBytes = blockSize * 4;

    // Count blocks ready
    let nBlocksReady = dataSigBytes / blockSizeBytes;
    if (doFlush) {
      // Round up to include partial blocks
      nBlocksReady = Math.ceil(nBlocksReady);
    } else {
      // Round down to include only full blocks,
      // less the number of blocks that must remain in the buffer
      nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
    }

    // Count words ready
    const nWordsReady = nBlocksReady * blockSize;

    // Count bytes ready
    const nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

    // Process blocks
    if (nWordsReady) {
      for (let offset = 0; offset < nWordsReady; offset += blockSize) {
        // Perform concrete-algorithm logic
        this._doProcessBlock(dataWords, offset);
      }

      // Remove processed words
      processedWords = dataWords.splice(0, nWordsReady);
      data.sigBytes -= nBytesReady;
    }

    // Return processed words
    return new WordArray(processedWords, nBytesReady);
  }

  /**
   * Creates a copy of this object.
   *
   * @return {Object} The clone.
   *
   * @example
   *
   *     var clone = bufferedBlockAlgorithm.clone();
   */
  clone() {
    const clone = super.clone.call(this);
    clone._data = this._data.clone();

    return clone;
  }
}

/**
 * Abstract hasher template.
 *
 * @property {number} blockSize
 *
 *     The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
 */
class Hasher extends BufferedBlockAlgorithm {
  constructor(cfg) {
    super();

    this.blockSize = 512 / 32;

    /**
     * Configuration options.
     */
    this.cfg = Object.assign(new Base(), cfg);

    // Set initial values
    this.reset();
  }

  /**
   * Creates a shortcut function to a hasher's object interface.
   *
   * @param {Hasher} SubHasher The hasher to create a helper for.
   *
   * @return {Function} The shortcut function.
   *
   * @static
   *
   * @example
   *
   *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
   */
  static _createHelper(SubHasher) {
    return (message, cfg) => new SubHasher(cfg).finalize(message);
  }

  /**
   * Creates a shortcut function to the HMAC's object interface.
   *
   * @param {Hasher} SubHasher The hasher to use in this HMAC helper.
   *
   * @return {Function} The shortcut function.
   *
   * @static
   *
   * @example
   *
   *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
   */
  static _createHmacHelper(SubHasher) {
    return (message, key) => new HMAC(SubHasher, key).finalize(message);
  }

  /**
   * Resets this hasher to its initial state.
   *
   * @example
   *
   *     hasher.reset();
   */
  reset() {
    // Reset data buffer
    super.reset.call(this);

    // Perform concrete-hasher logic
    this._doReset();
  }

  /**
   * Updates this hasher with a message.
   *
   * @param {WordArray|string} messageUpdate The message to append.
   *
   * @return {Hasher} This hasher.
   *
   * @example
   *
   *     hasher.update('message');
   *     hasher.update(wordArray);
   */
  update(messageUpdate) {
    // Append
    this._append(messageUpdate);

    // Update the hash
    this._process();

    // Chainable
    return this;
  }

  /**
   * Finalizes the hash computation.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param {WordArray|string} messageUpdate (Optional) A final message update.
   *
   * @return {WordArray} The hash.
   *
   * @example
   *
   *     var hash = hasher.finalize();
   *     var hash = hasher.finalize('message');
   *     var hash = hasher.finalize(wordArray);
   */
  finalize(messageUpdate) {
    // Final message update
    if (messageUpdate) {
      this._append(messageUpdate);
    }

    // Perform concrete-hasher logic
    const hash = this._doFinalize();

    return hash;
  }
}

/**
 * HMAC algorithm.
 */
class HMAC extends Base {
  /**
   * Initializes a newly created HMAC.
   *
   * @param {Hasher} SubHasher The hash algorithm to use.
   * @param {WordArray|string} key The secret key.
   *
   * @example
   *
   *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
   */
  constructor(SubHasher, key) {
    super();

    const hasher = new SubHasher();
    this._hasher = hasher;

    // Convert string to WordArray, else assume WordArray already
    let _key = key;
    if (typeof _key === 'string') {
      _key = Utf8.parse(_key);
    }

    // Shortcuts
    const hasherBlockSize = hasher.blockSize;
    const hasherBlockSizeBytes = hasherBlockSize * 4;

    // Allow arbitrary length keys
    if (_key.sigBytes > hasherBlockSizeBytes) {
      _key = hasher.finalize(key);
    }

    // Clamp excess bits
    _key.clamp();

    // Clone key for inner and outer pads
    const oKey = _key.clone();
    this._oKey = oKey;
    const iKey = _key.clone();
    this._iKey = iKey;

    // Shortcuts
    const oKeyWords = oKey.words;
    const iKeyWords = iKey.words;

    // XOR keys with pad constants
    for (let i = 0; i < hasherBlockSize; i += 1) {
      oKeyWords[i] ^= 0x5c5c5c5c;
      iKeyWords[i] ^= 0x36363636;
    }
    oKey.sigBytes = hasherBlockSizeBytes;
    iKey.sigBytes = hasherBlockSizeBytes;

    // Set initial values
    this.reset();
  }

  /**
   * Resets this HMAC to its initial state.
   *
   * @example
   *
   *     hmacHasher.reset();
   */
  reset() {
    // Shortcut
    const hasher = this._hasher;

    // Reset
    hasher.reset();
    hasher.update(this._iKey);
  }

  /**
   * Updates this HMAC with a message.
   *
   * @param {WordArray|string} messageUpdate The message to append.
   *
   * @return {HMAC} This HMAC instance.
   *
   * @example
   *
   *     hmacHasher.update('message');
   *     hmacHasher.update(wordArray);
   */
  update(messageUpdate) {
    this._hasher.update(messageUpdate);

    // Chainable
    return this;
  }

  /**
   * Finalizes the HMAC computation.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param {WordArray|string} messageUpdate (Optional) A final message update.
   *
   * @return {WordArray} The HMAC.
   *
   * @example
   *
   *     var hmac = hmacHasher.finalize();
   *     var hmac = hmacHasher.finalize('message');
   *     var hmac = hmacHasher.finalize(wordArray);
   */
  finalize(messageUpdate) {
    // Shortcut
    const hasher = this._hasher;

    // Compute HMAC
    const innerHash = hasher.finalize(messageUpdate);
    hasher.reset();
    const hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

    return hmac;
  }
}

const X32WordArray = WordArray;

/**
 * A 64-bit word.
 */
class X64Word extends Base {
  /**
   * Initializes a newly created 64-bit word.
   *
   * @param {number} high The high 32 bits.
   * @param {number} low The low 32 bits.
   *
   * @example
   *
   *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
   */
  constructor(high, low) {
    super();

    this.high = high;
    this.low = low;
  }
}

/**
 * An array of 64-bit words.
 *
 * @property {Array} words The array of CryptoJS.x64.Word objects.
 * @property {number} sigBytes The number of significant bytes in this word array.
 */
class X64WordArray extends Base {
  /**
   * Initializes a newly created word array.
   *
   * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
   * @param {number} sigBytes (Optional) The number of significant bytes in the words.
   *
   * @example
   *
   *     var wordArray = CryptoJS.x64.WordArray.create();
   *
   *     var wordArray = CryptoJS.x64.WordArray.create([
   *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
   *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
   *     ]);
   *
   *     var wordArray = CryptoJS.x64.WordArray.create([
   *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
   *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
   *     ], 10);
   */
  constructor(words = [], sigBytes = words.length * 8) {
    super();

    this.words = words;
    this.sigBytes = sigBytes;
  }

  /**
   * Converts this 64-bit word array to a 32-bit word array.
   *
   * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
   *
   * @example
   *
   *     var x32WordArray = x64WordArray.toX32();
   */
  toX32() {
    // Shortcuts
    const x64Words = this.words;
    const x64WordsLength = x64Words.length;

    // Convert
    const x32Words = [];
    for (let i = 0; i < x64WordsLength; i += 1) {
      const x64Word = x64Words[i];
      x32Words.push(x64Word.high);
      x32Words.push(x64Word.low);
    }

    return X32WordArray.create(x32Words, this.sigBytes);
  }

  /**
   * Creates a copy of this word array.
   *
   * @return {X64WordArray} The clone.
   *
   * @example
   *
   *     var clone = x64WordArray.clone();
   */
  clone() {
    const clone = super.clone.call(this);

    // Clone "words" array
    clone.words = this.words.slice(0);
    const { words } = clone;

    // Clone each X64Word object
    const wordsLength = words.length;
    for (let i = 0; i < wordsLength; i += 1) {
      words[i] = words[i].clone();
    }

    return clone;
  }
}

const parseLoop = (base64Str, base64StrLength, reverseMap) => {
  const words = [];
  let nBytes = 0;
  for (let i = 0; i < base64StrLength; i += 1) {
    if (i % 4) {
      const bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
      const bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
      const bitsCombined = bits1 | bits2;
      words[nBytes >>> 2] |= bitsCombined << (24 - (nBytes % 4) * 8);
      nBytes += 1;
    }
  }
  return WordArray.create(words, nBytes);
};

/**
 * Base64 encoding strategy.
 */
const Base64 = {
  /**
   * Converts a word array to a Base64 string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The Base64 string.
   *
   * @static
   *
   * @example
   *
   *     const base64String = CryptoJS.enc.Base64.stringify(wordArray);
   */
  stringify(wordArray) {
    // Shortcuts
    const { words, sigBytes } = wordArray;
    const map = this._map;

    // Clamp excess bits
    wordArray.clamp();

    // Convert
    const base64Chars = [];
    for (let i = 0; i < sigBytes; i += 3) {
      const byte1 = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
      const byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
      const byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

      const triplet = (byte1 << 16) | (byte2 << 8) | byte3;

      for (let j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j += 1) {
        base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
      }
    }

    // Add padding
    const paddingChar = map.charAt(64);
    if (paddingChar) {
      while (base64Chars.length % 4) {
        base64Chars.push(paddingChar);
      }
    }

    return base64Chars.join('');
  },

  /**
   * Converts a Base64 string to a word array.
   *
   * @param {string} base64Str The Base64 string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     const wordArray = CryptoJS.enc.Base64.parse(base64String);
   */
  parse(base64Str) {
    // Shortcuts
    let base64StrLength = base64Str.length;
    const map = this._map;
    let reverseMap = this._reverseMap;

    if (!reverseMap) {
      this._reverseMap = [];
      reverseMap = this._reverseMap;
      for (let j = 0; j < map.length; j += 1) {
        reverseMap[map.charCodeAt(j)] = j;
      }
    }

    // Ignore padding
    const paddingChar = map.charAt(64);
    if (paddingChar) {
      const paddingIndex = base64Str.indexOf(paddingChar);
      if (paddingIndex !== -1) {
        base64StrLength = paddingIndex;
      }
    }

    // Convert
    return parseLoop(base64Str, base64StrLength, reverseMap);
  },

  _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=',
};

// Constants table
const T$1 = [];

// Compute constants
for (let i = 0; i < 64; i += 1) {
  T$1[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
}

const FF = (a, b, c, d, x, s, t) => {
  const n = a + ((b & c) | (~b & d)) + x + t;
  return ((n << s) | (n >>> (32 - s))) + b;
};

const GG = (a, b, c, d, x, s, t) => {
  const n = a + ((b & d) | (c & ~d)) + x + t;
  return ((n << s) | (n >>> (32 - s))) + b;
};

const HH = (a, b, c, d, x, s, t) => {
  const n = a + (b ^ c ^ d) + x + t;
  return ((n << s) | (n >>> (32 - s))) + b;
};

const II = (a, b, c, d, x, s, t) => {
  const n = a + (c ^ (b | ~d)) + x + t;
  return ((n << s) | (n >>> (32 - s))) + b;
};

/**
 * MD5 hash algorithm.
 */
class MD5Algo extends Hasher {
  _doReset() {
    this._hash = new WordArray([
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476,
    ]);
  }

  _doProcessBlock(M, offset) {
    const _M = M;

    // Swap endian
    for (let i = 0; i < 16; i += 1) {
      // Shortcuts
      const offset_i = offset + i;
      const M_offset_i = M[offset_i];

      _M[offset_i] = (
        (((M_offset_i << 8) | (M_offset_i >>> 24)) & 0x00ff00ff)
          | (((M_offset_i << 24) | (M_offset_i >>> 8)) & 0xff00ff00)
      );
    }

    // Shortcuts
    const H = this._hash.words;

    const M_offset_0 = _M[offset + 0];
    const M_offset_1 = _M[offset + 1];
    const M_offset_2 = _M[offset + 2];
    const M_offset_3 = _M[offset + 3];
    const M_offset_4 = _M[offset + 4];
    const M_offset_5 = _M[offset + 5];
    const M_offset_6 = _M[offset + 6];
    const M_offset_7 = _M[offset + 7];
    const M_offset_8 = _M[offset + 8];
    const M_offset_9 = _M[offset + 9];
    const M_offset_10 = _M[offset + 10];
    const M_offset_11 = _M[offset + 11];
    const M_offset_12 = _M[offset + 12];
    const M_offset_13 = _M[offset + 13];
    const M_offset_14 = _M[offset + 14];
    const M_offset_15 = _M[offset + 15];

    // Working varialbes
    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];

    // Computation
    a = FF(a, b, c, d, M_offset_0, 7, T$1[0]);
    d = FF(d, a, b, c, M_offset_1, 12, T$1[1]);
    c = FF(c, d, a, b, M_offset_2, 17, T$1[2]);
    b = FF(b, c, d, a, M_offset_3, 22, T$1[3]);
    a = FF(a, b, c, d, M_offset_4, 7, T$1[4]);
    d = FF(d, a, b, c, M_offset_5, 12, T$1[5]);
    c = FF(c, d, a, b, M_offset_6, 17, T$1[6]);
    b = FF(b, c, d, a, M_offset_7, 22, T$1[7]);
    a = FF(a, b, c, d, M_offset_8, 7, T$1[8]);
    d = FF(d, a, b, c, M_offset_9, 12, T$1[9]);
    c = FF(c, d, a, b, M_offset_10, 17, T$1[10]);
    b = FF(b, c, d, a, M_offset_11, 22, T$1[11]);
    a = FF(a, b, c, d, M_offset_12, 7, T$1[12]);
    d = FF(d, a, b, c, M_offset_13, 12, T$1[13]);
    c = FF(c, d, a, b, M_offset_14, 17, T$1[14]);
    b = FF(b, c, d, a, M_offset_15, 22, T$1[15]);

    a = GG(a, b, c, d, M_offset_1, 5, T$1[16]);
    d = GG(d, a, b, c, M_offset_6, 9, T$1[17]);
    c = GG(c, d, a, b, M_offset_11, 14, T$1[18]);
    b = GG(b, c, d, a, M_offset_0, 20, T$1[19]);
    a = GG(a, b, c, d, M_offset_5, 5, T$1[20]);
    d = GG(d, a, b, c, M_offset_10, 9, T$1[21]);
    c = GG(c, d, a, b, M_offset_15, 14, T$1[22]);
    b = GG(b, c, d, a, M_offset_4, 20, T$1[23]);
    a = GG(a, b, c, d, M_offset_9, 5, T$1[24]);
    d = GG(d, a, b, c, M_offset_14, 9, T$1[25]);
    c = GG(c, d, a, b, M_offset_3, 14, T$1[26]);
    b = GG(b, c, d, a, M_offset_8, 20, T$1[27]);
    a = GG(a, b, c, d, M_offset_13, 5, T$1[28]);
    d = GG(d, a, b, c, M_offset_2, 9, T$1[29]);
    c = GG(c, d, a, b, M_offset_7, 14, T$1[30]);
    b = GG(b, c, d, a, M_offset_12, 20, T$1[31]);

    a = HH(a, b, c, d, M_offset_5, 4, T$1[32]);
    d = HH(d, a, b, c, M_offset_8, 11, T$1[33]);
    c = HH(c, d, a, b, M_offset_11, 16, T$1[34]);
    b = HH(b, c, d, a, M_offset_14, 23, T$1[35]);
    a = HH(a, b, c, d, M_offset_1, 4, T$1[36]);
    d = HH(d, a, b, c, M_offset_4, 11, T$1[37]);
    c = HH(c, d, a, b, M_offset_7, 16, T$1[38]);
    b = HH(b, c, d, a, M_offset_10, 23, T$1[39]);
    a = HH(a, b, c, d, M_offset_13, 4, T$1[40]);
    d = HH(d, a, b, c, M_offset_0, 11, T$1[41]);
    c = HH(c, d, a, b, M_offset_3, 16, T$1[42]);
    b = HH(b, c, d, a, M_offset_6, 23, T$1[43]);
    a = HH(a, b, c, d, M_offset_9, 4, T$1[44]);
    d = HH(d, a, b, c, M_offset_12, 11, T$1[45]);
    c = HH(c, d, a, b, M_offset_15, 16, T$1[46]);
    b = HH(b, c, d, a, M_offset_2, 23, T$1[47]);

    a = II(a, b, c, d, M_offset_0, 6, T$1[48]);
    d = II(d, a, b, c, M_offset_7, 10, T$1[49]);
    c = II(c, d, a, b, M_offset_14, 15, T$1[50]);
    b = II(b, c, d, a, M_offset_5, 21, T$1[51]);
    a = II(a, b, c, d, M_offset_12, 6, T$1[52]);
    d = II(d, a, b, c, M_offset_3, 10, T$1[53]);
    c = II(c, d, a, b, M_offset_10, 15, T$1[54]);
    b = II(b, c, d, a, M_offset_1, 21, T$1[55]);
    a = II(a, b, c, d, M_offset_8, 6, T$1[56]);
    d = II(d, a, b, c, M_offset_15, 10, T$1[57]);
    c = II(c, d, a, b, M_offset_6, 15, T$1[58]);
    b = II(b, c, d, a, M_offset_13, 21, T$1[59]);
    a = II(a, b, c, d, M_offset_4, 6, T$1[60]);
    d = II(d, a, b, c, M_offset_11, 10, T$1[61]);
    c = II(c, d, a, b, M_offset_2, 15, T$1[62]);
    b = II(b, c, d, a, M_offset_9, 21, T$1[63]);

    // Intermediate hash value
    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
  }
  /* eslint-ensable no-param-reassign */

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));

    const nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
    const nBitsTotalL = nBitsTotal;
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
      (((nBitsTotalH << 8) | (nBitsTotalH >>> 24)) & 0x00ff00ff)
        | (((nBitsTotalH << 24) | (nBitsTotalH >>> 8)) & 0xff00ff00)
    );
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
      (((nBitsTotalL << 8) | (nBitsTotalL >>> 24)) & 0x00ff00ff)
        | (((nBitsTotalL << 24) | (nBitsTotalL >>> 8)) & 0xff00ff00)
    );

    data.sigBytes = (dataWords.length + 1) * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const hash = this._hash;
    const H = hash.words;

    // Swap endian
    for (let i = 0; i < 4; i += 1) {
      // Shortcut
      const H_i = H[i];

      H[i] = (((H_i << 8) | (H_i >>> 24)) & 0x00ff00ff)
        | (((H_i << 24) | (H_i >>> 8)) & 0xff00ff00);
    }

    // Return final computed hash
    return hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.MD5('message');
 *     var hash = CryptoJS.MD5(wordArray);
 */
const MD5 = Hasher._createHelper(MD5Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacMD5(message, key);
 */
const HmacMD5 = Hasher._createHmacHelper(MD5Algo);

/**
 * This key derivation function is meant to conform with EVP_BytesToKey.
 * www.openssl.org/docs/crypto/EVP_BytesToKey.html
 */
class EvpKDFAlgo extends Base {
  /**
   * Initializes a newly created key derivation function.
   *
   * @param {Object} cfg (Optional) The configuration options to use for the derivation.
   *
   * @example
   *
   *     const kdf = CryptoJS.algo.EvpKDF.create();
   *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
   *     const kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
   */
  constructor(cfg) {
    super();

    /**
     * Configuration options.
     *
     * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
     * @property {Hasher} hasher The hash algorithm to use. Default: MD5
     * @property {number} iterations The number of iterations to perform. Default: 1
     */
    this.cfg = Object.assign(
      new Base(),
      {
        keySize: 128 / 32,
        hasher: MD5Algo,
        iterations: 1,
      },
      cfg,
    );
  }

  /**
   * Derives a key from a password.
   *
   * @param {WordArray|string} password The password.
   * @param {WordArray|string} salt A salt.
   *
   * @return {WordArray} The derived key.
   *
   * @example
   *
   *     const key = kdf.compute(password, salt);
   */
  compute(password, salt) {
    let block;

    // Shortcut
    const { cfg } = this;

    // Init hasher
    const hasher = cfg.hasher.create();

    // Initial values
    const derivedKey = WordArray.create();

    // Shortcuts
    const derivedKeyWords = derivedKey.words;
    const { keySize, iterations } = cfg;

    // Generate key
    while (derivedKeyWords.length < keySize) {
      if (block) {
        hasher.update(block);
      }
      block = hasher.update(password).finalize(salt);
      hasher.reset();

      // Iterations
      for (let i = 1; i < iterations; i += 1) {
        block = hasher.finalize(block);
        hasher.reset();
      }

      derivedKey.concat(block);
    }
    derivedKey.sigBytes = keySize * 4;

    return derivedKey;
  }
}

/**
 * Derives a key from a password.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {Object} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @static
 *
 * @example
 *
 *     var key = CryptoJS.EvpKDF(password, salt);
 *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
 *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
 */
const EvpKDF = (password, salt, cfg) => EvpKDFAlgo.create(cfg).compute(password, salt);

/* eslint-disable no-use-before-define */

/**
 * Abstract base cipher template.
 *
 * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
 * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
 * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
 * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
 */
class Cipher extends BufferedBlockAlgorithm {
  /**
   * Initializes a newly created cipher.
   *
   * @param {number} xformMode Either the encryption or decryption transormation mode constant.
   * @param {WordArray} key The key.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @example
   *
   *     const cipher = CryptoJS.algo.AES.create(
   *       CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray }
   *     );
   */
  constructor(xformMode, key, cfg) {
    super();

    /**
     * Configuration options.
     *
     * @property {WordArray} iv The IV to use for this operation.
     */
    this.cfg = Object.assign(new Base(), cfg);

    // Store transform mode and key
    this._xformMode = xformMode;
    this._key = key;

    // Set initial values
    this.reset();
  }

  /**
   * Creates this cipher in encryption mode.
   *
   * @param {WordArray} key The key.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {Cipher} A cipher instance.
   *
   * @static
   *
   * @example
   *
   *     const cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
   */
  static createEncryptor(key, cfg) {
    return this.create(this._ENC_XFORM_MODE, key, cfg);
  }

  /**
   * Creates this cipher in decryption mode.
   *
   * @param {WordArray} key The key.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {Cipher} A cipher instance.
   *
   * @static
   *
   * @example
   *
   *     const cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
   */
  static createDecryptor(key, cfg) {
    return this.create(this._DEC_XFORM_MODE, key, cfg);
  }

  /**
   * Creates shortcut functions to a cipher's object interface.
   *
   * @param {Cipher} cipher The cipher to create a helper for.
   *
   * @return {Object} An object with encrypt and decrypt shortcut functions.
   *
   * @static
   *
   * @example
   *
   *     const AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
   */
  static _createHelper(SubCipher) {
    const selectCipherStrategy = (key) => {
      if (typeof key === 'string') {
        return PasswordBasedCipher;
      }
      return SerializableCipher;
    };

    return {
      encrypt(message, key, cfg) {
        return selectCipherStrategy(key).encrypt(SubCipher, message, key, cfg);
      },

      decrypt(ciphertext, key, cfg) {
        return selectCipherStrategy(key).decrypt(SubCipher, ciphertext, key, cfg);
      },
    };
  }

  /**
   * Resets this cipher to its initial state.
   *
   * @example
   *
   *     cipher.reset();
   */
  reset() {
    // Reset data buffer
    super.reset.call(this);

    // Perform concrete-cipher logic
    this._doReset();
  }

  /**
   * Adds data to be encrypted or decrypted.
   *
   * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
   *
   * @return {WordArray} The data after processing.
   *
   * @example
   *
   *     const encrypted = cipher.process('data');
   *     const encrypted = cipher.process(wordArray);
   */
  process(dataUpdate) {
    // Append
    this._append(dataUpdate);

    // Process available blocks
    return this._process();
  }

  /**
   * Finalizes the encryption or decryption process.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
   *
   * @return {WordArray} The data after final processing.
   *
   * @example
   *
   *     const encrypted = cipher.finalize();
   *     const encrypted = cipher.finalize('data');
   *     const encrypted = cipher.finalize(wordArray);
   */
  finalize(dataUpdate) {
    // Final data update
    if (dataUpdate) {
      this._append(dataUpdate);
    }

    // Perform concrete-cipher logic
    const finalProcessedData = this._doFinalize();

    return finalProcessedData;
  }
}
Cipher._ENC_XFORM_MODE = 1;
Cipher._DEC_XFORM_MODE = 2;
Cipher.keySize = 128 / 32;
Cipher.ivSize = 128 / 32;

/**
 * Abstract base stream cipher template.
 *
 * @property {number} blockSize
 *
 *     The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
 */
class StreamCipher extends Cipher {
  constructor(...args) {
    super(...args);

    this.blockSize = 1;
  }

  _doFinalize() {
    // Process partial blocks
    const finalProcessedBlocks = this._process(!!'flush');

    return finalProcessedBlocks;
  }
}

/**
 * Abstract base block cipher mode template.
 */
class BlockCipherMode extends Base {
  /**
   * Initializes a newly created mode.
   *
   * @param {Cipher} cipher A block cipher instance.
   * @param {Array} iv The IV words.
   *
   * @example
   *
   *     const mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
   */
  constructor(cipher, iv) {
    super();

    this._cipher = cipher;
    this._iv = iv;
  }

  /**
   * Creates this mode for encryption.
   *
   * @param {Cipher} cipher A block cipher instance.
   * @param {Array} iv The IV words.
   *
   * @static
   *
   * @example
   *
   *     const mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
   */
  static createEncryptor(cipher, iv) {
    return this.Encryptor.create(cipher, iv);
  }

  /**
   * Creates this mode for decryption.
   *
   * @param {Cipher} cipher A block cipher instance.
   * @param {Array} iv The IV words.
   *
   * @static
   *
   * @example
   *
   *     const mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
   */
  static createDecryptor(cipher, iv) {
    return this.Decryptor.create(cipher, iv);
  }
}

function xorBlock(words, offset, blockSize) {
  const _words = words;
  let block;

  // Shortcut
  const iv = this._iv;

  // Choose mixing block
  if (iv) {
    block = iv;

    // Remove IV for subsequent blocks
    this._iv = undefined;
  } else {
    block = this._prevBlock;
  }

  // XOR blocks
  for (let i = 0; i < blockSize; i += 1) {
    _words[offset + i] ^= block[i];
  }
}

/**
 * Cipher Block Chaining mode.
 */

/**
 * Abstract base CBC mode.
 */
class CBC extends BlockCipherMode {
}
/**
 * CBC encryptor.
 */
CBC.Encryptor = class extends CBC {
  /**
   * Processes the data block at offset.
   *
   * @param {Array} words The data words to operate on.
   * @param {number} offset The offset where the block starts.
   *
   * @example
   *
   *     mode.processBlock(data.words, offset);
   */
  processBlock(words, offset) {
    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;

    // XOR and encrypt
    xorBlock.call(this, words, offset, blockSize);
    cipher.encryptBlock(words, offset);

    // Remember this block to use with next block
    this._prevBlock = words.slice(offset, offset + blockSize);
  }
};
/**
 * CBC decryptor.
 */
CBC.Decryptor = class extends CBC {
  /**
   * Processes the data block at offset.
   *
   * @param {Array} words The data words to operate on.
   * @param {number} offset The offset where the block starts.
   *
   * @example
   *
   *     mode.processBlock(data.words, offset);
   */
  processBlock(words, offset) {
    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;

    // Remember this block to use with next block
    const thisBlock = words.slice(offset, offset + blockSize);

    // Decrypt and XOR
    cipher.decryptBlock(words, offset);
    xorBlock.call(this, words, offset, blockSize);

    // This block becomes the previous block
    this._prevBlock = thisBlock;
  }
};

/**
 * PKCS #5/7 padding strategy.
 */
const Pkcs7 = {
  /**
   * Pads data using the algorithm defined in PKCS #5/7.
   *
   * @param {WordArray} data The data to pad.
   * @param {number} blockSize The multiple that the data should be padded to.
   *
   * @static
   *
   * @example
   *
   *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
   */
  pad(data, blockSize) {
    // Shortcut
    const blockSizeBytes = blockSize * 4;

    // Count padding bytes
    const nPaddingBytes = blockSizeBytes - (data.sigBytes % blockSizeBytes);

    // Create padding word
    const paddingWord = (nPaddingBytes << 24)
      | (nPaddingBytes << 16)
      | (nPaddingBytes << 8)
      | nPaddingBytes;

    // Create padding
    const paddingWords = [];
    for (let i = 0; i < nPaddingBytes; i += 4) {
      paddingWords.push(paddingWord);
    }
    const padding = WordArray.create(paddingWords, nPaddingBytes);

    // Add padding
    data.concat(padding);
  },

  /**
   * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
   *
   * @param {WordArray} data The data to unpad.
   *
   * @static
   *
   * @example
   *
   *     CryptoJS.pad.Pkcs7.unpad(wordArray);
   */
  unpad(data) {
    const _data = data;

    // Get number of padding bytes from last byte
    const nPaddingBytes = _data.words[(_data.sigBytes - 1) >>> 2] & 0xff;

    // Remove padding
    _data.sigBytes -= nPaddingBytes;
  },
};

/**
 * Abstract base block cipher template.
 *
 * @property {number} blockSize
 *
 *    The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
 */
class BlockCipher extends Cipher {
  constructor(xformMode, key, cfg) {
    /**
     * Configuration options.
     *
     * @property {Mode} mode The block mode to use. Default: CBC
     * @property {Padding} padding The padding strategy to use. Default: Pkcs7
     */
    super(xformMode, key, Object.assign(
      {
        mode: CBC,
        padding: Pkcs7,
      },
      cfg,
    ));

    this.blockSize = 128 / 32;
  }

  reset() {
    let modeCreator;

    // Reset cipher
    super.reset.call(this);

    // Shortcuts
    const { cfg } = this;
    const { iv, mode } = cfg;

    // Reset block mode
    if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
      modeCreator = mode.createEncryptor;
    } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
      modeCreator = mode.createDecryptor;
      // Keep at least one block in the buffer for unpadding
      this._minBufferSize = 1;
    }

    this._mode = modeCreator.call(mode, this, iv && iv.words);
    this._mode.__creator = modeCreator;
  }

  _doProcessBlock(words, offset) {
    this._mode.processBlock(words, offset);
  }

  _doFinalize() {
    let finalProcessedBlocks;

    // Shortcut
    const { padding } = this.cfg;

    // Finalize
    if (this._xformMode === this.constructor._ENC_XFORM_MODE) {
      // Pad data
      padding.pad(this._data, this.blockSize);

      // Process final blocks
      finalProcessedBlocks = this._process(!!'flush');
    } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
      // Process final blocks
      finalProcessedBlocks = this._process(!!'flush');

      // Unpad data
      padding.unpad(finalProcessedBlocks);
    }

    return finalProcessedBlocks;
  }
}

/**
 * A collection of cipher parameters.
 *
 * @property {WordArray} ciphertext The raw ciphertext.
 * @property {WordArray} key The key to this ciphertext.
 * @property {WordArray} iv The IV used in the ciphering operation.
 * @property {WordArray} salt The salt used with a key derivation function.
 * @property {Cipher} algorithm The cipher algorithm.
 * @property {Mode} mode The block mode used in the ciphering operation.
 * @property {Padding} padding The padding scheme used in the ciphering operation.
 * @property {number} blockSize The block size of the cipher.
 * @property {Format} formatter
 *    The default formatting strategy to convert this cipher params object to a string.
 */
class CipherParams extends Base {
  /**
   * Initializes a newly created cipher params object.
   *
   * @param {Object} cipherParams An object with any of the possible cipher parameters.
   *
   * @example
   *
   *     var cipherParams = CryptoJS.lib.CipherParams.create({
   *         ciphertext: ciphertextWordArray,
   *         key: keyWordArray,
   *         iv: ivWordArray,
   *         salt: saltWordArray,
   *         algorithm: CryptoJS.algo.AES,
   *         mode: CryptoJS.mode.CBC,
   *         padding: CryptoJS.pad.PKCS7,
   *         blockSize: 4,
   *         formatter: CryptoJS.format.OpenSSL
   *     });
   */
  constructor(cipherParams) {
    super();

    this.mixIn(cipherParams);
  }

  /**
   * Converts this cipher params object to a string.
   *
   * @param {Format} formatter (Optional) The formatting strategy to use.
   *
   * @return {string} The stringified cipher params.
   *
   * @throws Error If neither the formatter nor the default formatter is set.
   *
   * @example
   *
   *     var string = cipherParams + '';
   *     var string = cipherParams.toString();
   *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
   */
  toString(formatter) {
    return (formatter || this.formatter).stringify(this);
  }
}

/**
 * OpenSSL formatting strategy.
 */
const OpenSSLFormatter = {
  /**
   * Converts a cipher params object to an OpenSSL-compatible string.
   *
   * @param {CipherParams} cipherParams The cipher params object.
   *
   * @return {string} The OpenSSL-compatible string.
   *
   * @static
   *
   * @example
   *
   *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
   */
  stringify(cipherParams) {
    let wordArray;

    // Shortcuts
    const { ciphertext, salt } = cipherParams;

    // Format
    if (salt) {
      wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
    } else {
      wordArray = ciphertext;
    }

    return wordArray.toString(Base64);
  },

  /**
   * Converts an OpenSSL-compatible string to a cipher params object.
   *
   * @param {string} openSSLStr The OpenSSL-compatible string.
   *
   * @return {CipherParams} The cipher params object.
   *
   * @static
   *
   * @example
   *
   *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
   */
  parse(openSSLStr) {
    let salt;

    // Parse base64
    const ciphertext = Base64.parse(openSSLStr);

    // Shortcut
    const ciphertextWords = ciphertext.words;

    // Test for salt
    if (ciphertextWords[0] === 0x53616c74 && ciphertextWords[1] === 0x65645f5f) {
      // Extract salt
      salt = WordArray.create(ciphertextWords.slice(2, 4));

      // Remove salt from ciphertext
      ciphertextWords.splice(0, 4);
      ciphertext.sigBytes -= 16;
    }

    return CipherParams.create({ ciphertext, salt });
  },
};

/**
 * A cipher wrapper that returns ciphertext as a serializable cipher params object.
 */
class SerializableCipher extends Base {
  /**
   * Encrypts a message.
   *
   * @param {Cipher} cipher The cipher algorithm to use.
   * @param {WordArray|string} message The message to encrypt.
   * @param {WordArray} key The key.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {CipherParams} A cipher params object.
   *
   * @static
   *
   * @example
   *
   *     var ciphertextParams = CryptoJS.lib.SerializableCipher
   *       .encrypt(CryptoJS.algo.AES, message, key);
   *     var ciphertextParams = CryptoJS.lib.SerializableCipher
   *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
   *     var ciphertextParams = CryptoJS.lib.SerializableCipher
   *       .encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
   */
  static encrypt(cipher, message, key, cfg) {
    // Apply config defaults
    const _cfg = Object.assign(new Base(), this.cfg, cfg);

    // Encrypt
    const encryptor = cipher.createEncryptor(key, _cfg);
    const ciphertext = encryptor.finalize(message);

    // Shortcut
    const cipherCfg = encryptor.cfg;

    // Create and return serializable cipher params
    return CipherParams.create({
      ciphertext,
      key,
      iv: cipherCfg.iv,
      algorithm: cipher,
      mode: cipherCfg.mode,
      padding: cipherCfg.padding,
      blockSize: encryptor.blockSize,
      formatter: _cfg.format,
    });
  }

  /**
   * Decrypts serialized ciphertext.
   *
   * @param {Cipher} cipher The cipher algorithm to use.
   * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
   * @param {WordArray} key The key.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {WordArray} The plaintext.
   *
   * @static
   *
   * @example
   *
   *     var plaintext = CryptoJS.lib.SerializableCipher
   *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, key,
   *         { iv: iv, format: CryptoJS.format.OpenSSL });
   *     var plaintext = CryptoJS.lib.SerializableCipher
   *       .decrypt(CryptoJS.algo.AES, ciphertextParams, key,
   *         { iv: iv, format: CryptoJS.format.OpenSSL });
   */
  static decrypt(cipher, ciphertext, key, cfg) {
    let _ciphertext = ciphertext;

    // Apply config defaults
    const _cfg = Object.assign(new Base(), this.cfg, cfg);

    // Convert string to CipherParams
    _ciphertext = this._parse(_ciphertext, _cfg.format);

    // Decrypt
    const plaintext = cipher.createDecryptor(key, _cfg).finalize(_ciphertext.ciphertext);

    return plaintext;
  }

  /**
   * Converts serialized ciphertext to CipherParams,
   * else assumed CipherParams already and returns ciphertext unchanged.
   *
   * @param {CipherParams|string} ciphertext The ciphertext.
   * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
   *
   * @return {CipherParams} The unserialized ciphertext.
   *
   * @static
   *
   * @example
   *
   *     var ciphertextParams = CryptoJS.lib.SerializableCipher
   *       ._parse(ciphertextStringOrParams, format);
   */
  static _parse(ciphertext, format) {
    if (typeof ciphertext === 'string') {
      return format.parse(ciphertext, this);
    }
    return ciphertext;
  }
}
/**
 * Configuration options.
 *
 * @property {Formatter} format
 *
 *    The formatting strategy to convert cipher param objects to and from a string.
 *    Default: OpenSSL
 */
SerializableCipher.cfg = Object.assign(
  new Base(),
  { format: OpenSSLFormatter },
);

/**
 * OpenSSL key derivation function.
 */
const OpenSSLKdf = {
  /**
   * Derives a key and IV from a password.
   *
   * @param {string} password The password to derive from.
   * @param {number} keySize The size in words of the key to generate.
   * @param {number} ivSize The size in words of the IV to generate.
   * @param {WordArray|string} salt
   *     (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
   *
   * @return {CipherParams} A cipher params object with the key, IV, and salt.
   *
   * @static
   *
   * @example
   *
   *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
   *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
   */
  execute(password, keySize, ivSize, salt) {
    let _salt = salt;

    // Generate random salt
    if (!_salt) {
      _salt = WordArray.random(64 / 8);
    }

    // Derive key and IV
    const key = EvpKDFAlgo.create({ keySize: keySize + ivSize }).compute(password, _salt);

    // Separate key and IV
    const iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
    key.sigBytes = keySize * 4;

    // Return params
    return CipherParams.create({ key, iv, salt: _salt });
  },
};

/**
 * A serializable cipher wrapper that derives the key from a password,
 * and returns ciphertext as a serializable cipher params object.
 */
class PasswordBasedCipher extends SerializableCipher {
  /**
   * Encrypts a message using a password.
   *
   * @param {Cipher} cipher The cipher algorithm to use.
   * @param {WordArray|string} message The message to encrypt.
   * @param {string} password The password.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {CipherParams} A cipher params object.
   *
   * @static
   *
   * @example
   *
   *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
   *       .encrypt(CryptoJS.algo.AES, message, 'password');
   *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher
   *       .encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
   */
  static encrypt(cipher, message, password, cfg) {
    // Apply config defaults
    const _cfg = Object.assign(new Base(), this.cfg, cfg);

    // Derive key and other params
    const derivedParams = _cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

    // Add IV to config
    _cfg.iv = derivedParams.iv;

    // Encrypt
    const ciphertext = SerializableCipher.encrypt
      .call(this, cipher, message, derivedParams.key, _cfg);

    // Mix in derived params
    ciphertext.mixIn(derivedParams);

    return ciphertext;
  }

  /**
   * Decrypts serialized ciphertext using a password.
   *
   * @param {Cipher} cipher The cipher algorithm to use.
   * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
   * @param {string} password The password.
   * @param {Object} cfg (Optional) The configuration options to use for this operation.
   *
   * @return {WordArray} The plaintext.
   *
   * @static
   *
   * @example
   *
   *     var plaintext = CryptoJS.lib.PasswordBasedCipher
   *       .decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password',
   *         { format: CryptoJS.format.OpenSSL });
   *     var plaintext = CryptoJS.lib.PasswordBasedCipher
   *       .decrypt(CryptoJS.algo.AES, ciphertextParams, 'password',
   *         { format: CryptoJS.format.OpenSSL });
   */
  static decrypt(cipher, ciphertext, password, cfg) {
    let _ciphertext = ciphertext;

    // Apply config defaults
    const _cfg = Object.assign(new Base(), this.cfg, cfg);

    // Convert string to CipherParams
    _ciphertext = this._parse(_ciphertext, _cfg.format);

    // Derive key and other params
    const derivedParams = _cfg.kdf
      .execute(password, cipher.keySize, cipher.ivSize, _ciphertext.salt);

    // Add IV to config
    _cfg.iv = derivedParams.iv;

    // Decrypt
    const plaintext = SerializableCipher.decrypt
      .call(this, cipher, _ciphertext, derivedParams.key, _cfg);

    return plaintext;
  }
}
/**
 * Configuration options.
 *
 * @property {KDF} kdf
 *     The key derivation function to use to generate a key and IV from a password.
 *     Default: OpenSSL
 */
PasswordBasedCipher.cfg = Object.assign(SerializableCipher.cfg, { kdf: OpenSSLKdf });

const swapEndian = word => ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);

/**
 * UTF-16 BE encoding strategy.
 */
const Utf16BE = {
  /**
   * Converts a word array to a UTF-16 BE string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The UTF-16 BE string.
   *
   * @static
   *
   * @example
   *
   *     const utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
   */
  stringify(wordArray) {
    // Shortcuts
    const { words, sigBytes } = wordArray;

    // Convert
    const utf16Chars = [];
    for (let i = 0; i < sigBytes; i += 2) {
      const codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
      utf16Chars.push(String.fromCharCode(codePoint));
    }

    return utf16Chars.join('');
  },

  /**
   * Converts a UTF-16 BE string to a word array.
   *
   * @param {string} utf16Str The UTF-16 BE string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     const wordArray = CryptoJS.enc.Utf16.parse(utf16String);
   */
  parse(utf16Str) {
    // Shortcut
    const utf16StrLength = utf16Str.length;

    // Convert
    const words = [];
    for (let i = 0; i < utf16StrLength; i += 1) {
      words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
    }

    return WordArray.create(words, utf16StrLength * 2);
  },
};
const Utf16 = Utf16BE;

/**
 * UTF-16 LE encoding strategy.
 */
const Utf16LE = {
  /**
   * Converts a word array to a UTF-16 LE string.
   *
   * @param {WordArray} wordArray The word array.
   *
   * @return {string} The UTF-16 LE string.
   *
   * @static
   *
   * @example
   *
   *     const utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
   */
  stringify(wordArray) {
    // Shortcuts
    const { words, sigBytes } = wordArray;

    // Convert
    const utf16Chars = [];
    for (let i = 0; i < sigBytes; i += 2) {
      const codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
      utf16Chars.push(String.fromCharCode(codePoint));
    }

    return utf16Chars.join('');
  },

  /**
   * Converts a UTF-16 LE string to a word array.
   *
   * @param {string} utf16Str The UTF-16 LE string.
   *
   * @return {WordArray} The word array.
   *
   * @static
   *
   * @example
   *
   *     const wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
   */
  parse(utf16Str) {
    // Shortcut
    const utf16StrLength = utf16Str.length;

    // Convert
    const words = [];
    for (let i = 0; i < utf16StrLength; i += 1) {
      words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
    }

    return WordArray.create(words, utf16StrLength * 2);
  },
};

// Reusable object
const W$2 = [];

/**
 * SHA-1 hash algorithm.
 */
class SHA1Algo extends Hasher {
  _doReset() {
    this._hash = new WordArray([
      0x67452301,
      0xefcdab89,
      0x98badcfe,
      0x10325476,
      0xc3d2e1f0,
    ]);
  }

  _doProcessBlock(M, offset) {
    // Shortcut
    const H = this._hash.words;

    // Working variables
    let a = H[0];
    let b = H[1];
    let c = H[2];
    let d = H[3];
    let e = H[4];

    // Computation
    for (let i = 0; i < 80; i += 1) {
      if (i < 16) {
        W$2[i] = M[offset + i] | 0;
      } else {
        const n = W$2[i - 3] ^ W$2[i - 8] ^ W$2[i - 14] ^ W$2[i - 16];
        W$2[i] = (n << 1) | (n >>> 31);
      }

      let t = ((a << 5) | (a >>> 27)) + e + W$2[i];
      if (i < 20) {
        t += ((b & c) | (~b & d)) + 0x5a827999;
      } else if (i < 40) {
        t += (b ^ c ^ d) + 0x6ed9eba1;
      } else if (i < 60) {
        t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
      } else /* if (i < 80) */ {
        t += (b ^ c ^ d) - 0x359d3e2a;
      }

      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }

    // Intermediate hash value
    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Return final computed hash
    return this._hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA1('message');
 *     var hash = CryptoJS.SHA1(wordArray);
 */
const SHA1 = Hasher._createHelper(SHA1Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA1(message, key);
 */
const HmacSHA1 = Hasher._createHmacHelper(SHA1Algo);

// Initialization and round constants tables
const H = [];
const K$1 = [];

// Compute constants
const isPrime = (n) => {
  const sqrtN = Math.sqrt(n);
  for (let factor = 2; factor <= sqrtN; factor += 1) {
    if (!(n % factor)) {
      return false;
    }
  }

  return true;
};

const getFractionalBits = n => ((n - (n | 0)) * 0x100000000) | 0;

let n = 2;
let nPrime = 0;
while (nPrime < 64) {
  if (isPrime(n)) {
    if (nPrime < 8) {
      H[nPrime] = getFractionalBits(n ** (1 / 2));
    }
    K$1[nPrime] = getFractionalBits(n ** (1 / 3));

    nPrime += 1;
  }

  n += 1;
}

// Reusable object
const W$1 = [];

/**
 * SHA-256 hash algorithm.
 */
class SHA256Algo extends Hasher {
  _doReset() {
    this._hash = new WordArray(H.slice(0));
  }

  _doProcessBlock(M, offset) {
    // Shortcut
    const _H = this._hash.words;

    // Working variables
    let a = _H[0];
    let b = _H[1];
    let c = _H[2];
    let d = _H[3];
    let e = _H[4];
    let f = _H[5];
    let g = _H[6];
    let h = _H[7];

    // Computation
    for (let i = 0; i < 64; i += 1) {
      if (i < 16) {
        W$1[i] = M[offset + i] | 0;
      } else {
        const gamma0x = W$1[i - 15];
        const gamma0 = ((gamma0x << 25) | (gamma0x >>> 7))
          ^ ((gamma0x << 14) | (gamma0x >>> 18))
          ^ (gamma0x >>> 3);

        const gamma1x = W$1[i - 2];
        const gamma1 = ((gamma1x << 15) | (gamma1x >>> 17))
          ^ ((gamma1x << 13) | (gamma1x >>> 19))
          ^ (gamma1x >>> 10);

        W$1[i] = gamma0 + W$1[i - 7] + gamma1 + W$1[i - 16];
      }

      const ch = (e & f) ^ (~e & g);
      const maj = (a & b) ^ (a & c) ^ (b & c);

      const sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
      const sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7) | (e >>> 25));

      const t1 = h + sigma1 + ch + K$1[i] + W$1[i];
      const t2 = sigma0 + maj;

      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }

    // Intermediate hash value
    _H[0] = (_H[0] + a) | 0;
    _H[1] = (_H[1] + b) | 0;
    _H[2] = (_H[2] + c) | 0;
    _H[3] = (_H[3] + d) | 0;
    _H[4] = (_H[4] + e) | 0;
    _H[5] = (_H[5] + f) | 0;
    _H[6] = (_H[6] + g) | 0;
    _H[7] = (_H[7] + h) | 0;
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Return final computed hash
    return this._hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA256('message');
 *     var hash = CryptoJS.SHA256(wordArray);
 */
const SHA256 = Hasher._createHelper(SHA256Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA256(message, key);
 */
const HmacSHA256 = Hasher._createHmacHelper(SHA256Algo);

/**
 * SHA-224 hash algorithm.
 */
class SHA224Algo extends SHA256Algo {
  _doReset() {
    this._hash = new WordArray([
      0xc1059ed8,
      0x367cd507,
      0x3070dd17,
      0xf70e5939,
      0xffc00b31,
      0x68581511,
      0x64f98fa7,
      0xbefa4fa4,
    ]);
  }

  _doFinalize() {
    const hash = super._doFinalize.call(this);

    hash.sigBytes -= 4;

    return hash;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA224('message');
 *     var hash = CryptoJS.SHA224(wordArray);
 */
const SHA224 = SHA256Algo._createHelper(SHA224Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA224(message, key);
 */
const HmacSHA224 = SHA256Algo._createHmacHelper(SHA224Algo);

// Constants
const K = [
  new X64Word(0x428a2f98, 0xd728ae22),
  new X64Word(0x71374491, 0x23ef65cd),
  new X64Word(0xb5c0fbcf, 0xec4d3b2f),
  new X64Word(0xe9b5dba5, 0x8189dbbc),
  new X64Word(0x3956c25b, 0xf348b538),
  new X64Word(0x59f111f1, 0xb605d019),
  new X64Word(0x923f82a4, 0xaf194f9b),
  new X64Word(0xab1c5ed5, 0xda6d8118),
  new X64Word(0xd807aa98, 0xa3030242),
  new X64Word(0x12835b01, 0x45706fbe),
  new X64Word(0x243185be, 0x4ee4b28c),
  new X64Word(0x550c7dc3, 0xd5ffb4e2),
  new X64Word(0x72be5d74, 0xf27b896f),
  new X64Word(0x80deb1fe, 0x3b1696b1),
  new X64Word(0x9bdc06a7, 0x25c71235),
  new X64Word(0xc19bf174, 0xcf692694),
  new X64Word(0xe49b69c1, 0x9ef14ad2),
  new X64Word(0xefbe4786, 0x384f25e3),
  new X64Word(0x0fc19dc6, 0x8b8cd5b5),
  new X64Word(0x240ca1cc, 0x77ac9c65),
  new X64Word(0x2de92c6f, 0x592b0275),
  new X64Word(0x4a7484aa, 0x6ea6e483),
  new X64Word(0x5cb0a9dc, 0xbd41fbd4),
  new X64Word(0x76f988da, 0x831153b5),
  new X64Word(0x983e5152, 0xee66dfab),
  new X64Word(0xa831c66d, 0x2db43210),
  new X64Word(0xb00327c8, 0x98fb213f),
  new X64Word(0xbf597fc7, 0xbeef0ee4),
  new X64Word(0xc6e00bf3, 0x3da88fc2),
  new X64Word(0xd5a79147, 0x930aa725),
  new X64Word(0x06ca6351, 0xe003826f),
  new X64Word(0x14292967, 0x0a0e6e70),
  new X64Word(0x27b70a85, 0x46d22ffc),
  new X64Word(0x2e1b2138, 0x5c26c926),
  new X64Word(0x4d2c6dfc, 0x5ac42aed),
  new X64Word(0x53380d13, 0x9d95b3df),
  new X64Word(0x650a7354, 0x8baf63de),
  new X64Word(0x766a0abb, 0x3c77b2a8),
  new X64Word(0x81c2c92e, 0x47edaee6),
  new X64Word(0x92722c85, 0x1482353b),
  new X64Word(0xa2bfe8a1, 0x4cf10364),
  new X64Word(0xa81a664b, 0xbc423001),
  new X64Word(0xc24b8b70, 0xd0f89791),
  new X64Word(0xc76c51a3, 0x0654be30),
  new X64Word(0xd192e819, 0xd6ef5218),
  new X64Word(0xd6990624, 0x5565a910),
  new X64Word(0xf40e3585, 0x5771202a),
  new X64Word(0x106aa070, 0x32bbd1b8),
  new X64Word(0x19a4c116, 0xb8d2d0c8),
  new X64Word(0x1e376c08, 0x5141ab53),
  new X64Word(0x2748774c, 0xdf8eeb99),
  new X64Word(0x34b0bcb5, 0xe19b48a8),
  new X64Word(0x391c0cb3, 0xc5c95a63),
  new X64Word(0x4ed8aa4a, 0xe3418acb),
  new X64Word(0x5b9cca4f, 0x7763e373),
  new X64Word(0x682e6ff3, 0xd6b2b8a3),
  new X64Word(0x748f82ee, 0x5defb2fc),
  new X64Word(0x78a5636f, 0x43172f60),
  new X64Word(0x84c87814, 0xa1f0ab72),
  new X64Word(0x8cc70208, 0x1a6439ec),
  new X64Word(0x90befffa, 0x23631e28),
  new X64Word(0xa4506ceb, 0xde82bde9),
  new X64Word(0xbef9a3f7, 0xb2c67915),
  new X64Word(0xc67178f2, 0xe372532b),
  new X64Word(0xca273ece, 0xea26619c),
  new X64Word(0xd186b8c7, 0x21c0c207),
  new X64Word(0xeada7dd6, 0xcde0eb1e),
  new X64Word(0xf57d4f7f, 0xee6ed178),
  new X64Word(0x06f067aa, 0x72176fba),
  new X64Word(0x0a637dc5, 0xa2c898a6),
  new X64Word(0x113f9804, 0xbef90dae),
  new X64Word(0x1b710b35, 0x131c471b),
  new X64Word(0x28db77f5, 0x23047d84),
  new X64Word(0x32caab7b, 0x40c72493),
  new X64Word(0x3c9ebe0a, 0x15c9bebc),
  new X64Word(0x431d67c4, 0x9c100d4c),
  new X64Word(0x4cc5d4be, 0xcb3e42b6),
  new X64Word(0x597f299c, 0xfc657e2a),
  new X64Word(0x5fcb6fab, 0x3ad6faec),
  new X64Word(0x6c44198c, 0x4a475817),
];

// Reusable objects
const W = [];
for (let i = 0; i < 80; i += 1) {
  W[i] = new X64Word();
}

/**
 * SHA-512 hash algorithm.
 */
class SHA512Algo extends Hasher {
  constructor() {
    super();

    this.blockSize = 1024 / 32;
  }

  _doReset() {
    this._hash = new X64WordArray([
      new X64Word(0x6a09e667, 0xf3bcc908),
      new X64Word(0xbb67ae85, 0x84caa73b),
      new X64Word(0x3c6ef372, 0xfe94f82b),
      new X64Word(0xa54ff53a, 0x5f1d36f1),
      new X64Word(0x510e527f, 0xade682d1),
      new X64Word(0x9b05688c, 0x2b3e6c1f),
      new X64Word(0x1f83d9ab, 0xfb41bd6b),
      new X64Word(0x5be0cd19, 0x137e2179),
    ]);
  }

  _doProcessBlock(M, offset) {
    // Shortcuts
    const H = this._hash.words;

    const H0 = H[0];
    const H1 = H[1];
    const H2 = H[2];
    const H3 = H[3];
    const H4 = H[4];
    const H5 = H[5];
    const H6 = H[6];
    const H7 = H[7];

    const H0h = H0.high;
    let H0l = H0.low;
    const H1h = H1.high;
    let H1l = H1.low;
    const H2h = H2.high;
    let H2l = H2.low;
    const H3h = H3.high;
    let H3l = H3.low;
    const H4h = H4.high;
    let H4l = H4.low;
    const H5h = H5.high;
    let H5l = H5.low;
    const H6h = H6.high;
    let H6l = H6.low;
    const H7h = H7.high;
    let H7l = H7.low;

    // Working variables
    let ah = H0h;
    let al = H0l;
    let bh = H1h;
    let bl = H1l;
    let ch = H2h;
    let cl = H2l;
    let dh = H3h;
    let dl = H3l;
    let eh = H4h;
    let el = H4l;
    let fh = H5h;
    let fl = H5l;
    let gh = H6h;
    let gl = H6l;
    let hh = H7h;
    let hl = H7l;

    // Rounds
    for (let i = 0; i < 80; i += 1) {
      let Wil;
      let Wih;

      // Shortcut
      const Wi = W[i];

      // Extend message
      if (i < 16) {
        Wi.high = M[offset + i * 2] | 0;
        Wih = Wi.high;
        Wi.low = M[offset + i * 2 + 1] | 0;
        Wil = Wi.low;
      } else {
        // Gamma0
        const gamma0x = W[i - 15];
        const gamma0xh = gamma0x.high;
        const gamma0xl = gamma0x.low;
        const gamma0h = ((gamma0xh >>> 1) | (gamma0xl << 31))
          ^ ((gamma0xh >>> 8) | (gamma0xl << 24))
          ^ (gamma0xh >>> 7);
        const gamma0l = ((gamma0xl >>> 1) | (gamma0xh << 31))
          ^ ((gamma0xl >>> 8) | (gamma0xh << 24))
          ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

        // Gamma1
        const gamma1x = W[i - 2];
        const gamma1xh = gamma1x.high;
        const gamma1xl = gamma1x.low;
        const gamma1h = ((gamma1xh >>> 19) | (gamma1xl << 13))
          ^ ((gamma1xh << 3) | (gamma1xl >>> 29))
          ^ (gamma1xh >>> 6);
        const gamma1l = ((gamma1xl >>> 19) | (gamma1xh << 13))
          ^ ((gamma1xl << 3) | (gamma1xh >>> 29))
          ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

        // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
        const Wi7 = W[i - 7];
        const Wi7h = Wi7.high;
        const Wi7l = Wi7.low;

        const Wi16 = W[i - 16];
        const Wi16h = Wi16.high;
        const Wi16l = Wi16.low;

        Wil = gamma0l + Wi7l;
        Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
        Wil += gamma1l;
        Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
        Wil += Wi16l;
        Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

        Wi.high = Wih;
        Wi.low = Wil;
      }

      const chh = (eh & fh) ^ (~eh & gh);
      const chl = (el & fl) ^ (~el & gl);
      const majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
      const majl = (al & bl) ^ (al & cl) ^ (bl & cl);

      const sigma0h = ((ah >>> 28) | (al << 4))
        ^ ((ah << 30) | (al >>> 2))
        ^ ((ah << 25) | (al >>> 7));
      const sigma0l = ((al >>> 28) | (ah << 4))
        ^ ((al << 30) | (ah >>> 2))
        ^ ((al << 25) | (ah >>> 7));
      const sigma1h = ((eh >>> 14) | (el << 18))
        ^ ((eh >>> 18) | (el << 14))
        ^ ((eh << 23) | (el >>> 9));
      const sigma1l = ((el >>> 14) | (eh << 18))
        ^ ((el >>> 18) | (eh << 14))
        ^ ((el << 23) | (eh >>> 9));

      // t1 = h + sigma1 + ch + K[i] + W[i]
      const Ki = K[i];
      const Kih = Ki.high;
      const Kil = Ki.low;

      let t1l = hl + sigma1l;
      let t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
      t1l += chl;
      t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
      t1l += Kil;
      t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
      t1l += Wil;
      t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

      // t2 = sigma0 + maj
      const t2l = sigma0l + majl;
      const t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

      // Update working variables
      hh = gh;
      hl = gl;
      gh = fh;
      gl = fl;
      fh = eh;
      fl = el;
      el = (dl + t1l) | 0;
      eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
      dh = ch;
      dl = cl;
      ch = bh;
      cl = bl;
      bh = ah;
      bl = al;
      al = (t1l + t2l) | 0;
      ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
    }

    // Intermediate hash value
    H0.low = (H0l + al);
    H0l = H0.low;
    H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
    H1.low = (H1l + bl);
    H1l = H1.low;
    H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
    H2.low = (H2l + cl);
    H2l = H2.low;
    H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
    H3.low = (H3l + dl);
    H3l = H3.low;
    H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
    H4.low = (H4l + el);
    H4l = H4.low;
    H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
    H5.low = (H5l + fl);
    H5l = H5.low;
    H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
    H6.low = (H6l + gl);
    H6l = H6.low;
    H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
    H7.low = (H7l + hl);
    H7l = H7.low;
    H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
    dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Convert hash to 32-bit word array before returning
    const hash = this._hash.toX32();

    // Return final computed hash
    return hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA512('message');
 *     var hash = CryptoJS.SHA512(wordArray);
 */
const SHA512 = Hasher._createHelper(SHA512Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA512(message, key);
 */
const HmacSHA512 = Hasher._createHmacHelper(SHA512Algo);

/**
 * SHA-384 hash algorithm.
 */
class SHA384Algo extends SHA512Algo {
  _doReset() {
    this._hash = new X64WordArray([
      new X64Word(0xcbbb9d5d, 0xc1059ed8),
      new X64Word(0x629a292a, 0x367cd507),
      new X64Word(0x9159015a, 0x3070dd17),
      new X64Word(0x152fecd8, 0xf70e5939),
      new X64Word(0x67332667, 0xffc00b31),
      new X64Word(0x8eb44a87, 0x68581511),
      new X64Word(0xdb0c2e0d, 0x64f98fa7),
      new X64Word(0x47b5481d, 0xbefa4fa4),
    ]);
  }

  _doFinalize() {
    const hash = super._doFinalize.call(this);

    hash.sigBytes -= 16;

    return hash;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA384('message');
 *     var hash = CryptoJS.SHA384(wordArray);
 */
const SHA384 = SHA512Algo._createHelper(SHA384Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA384(message, key);
 */
const HmacSHA384 = SHA512Algo._createHmacHelper(SHA384Algo);

// Constants tables
const RHO_OFFSETS = [];
const PI_INDEXES = [];
const ROUND_CONSTANTS = [];

// Compute Constants
// Compute rho offset constants
let _x = 1;
let _y = 0;
for (let t = 0; t < 24; t += 1) {
  RHO_OFFSETS[_x + 5 * _y] = ((t + 1) * (t + 2) / 2) % 64;

  const newX = _y % 5;
  const newY = (2 * _x + 3 * _y) % 5;
  _x = newX;
  _y = newY;
}

// Compute pi index constants
for (let x = 0; x < 5; x += 1) {
  for (let y = 0; y < 5; y += 1) {
    PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
  }
}

// Compute round constants
let LFSR = 0x01;
for (let i = 0; i < 24; i += 1) {
  let roundConstantMsw = 0;
  let roundConstantLsw = 0;

  for (let j = 0; j < 7; j += 1) {
    if (LFSR & 0x01) {
      const bitPosition = (1 << j) - 1;
      if (bitPosition < 32) {
        roundConstantLsw ^= 1 << bitPosition;
      } else /* if (bitPosition >= 32) */ {
        roundConstantMsw ^= 1 << (bitPosition - 32);
      }
    }

    // Compute next LFSR
    if (LFSR & 0x80) {
      // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
      LFSR = (LFSR << 1) ^ 0x71;
    } else {
      LFSR <<= 1;
    }
  }

  ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
}

// Reusable objects for temporary values
const T = [];
for (let i = 0; i < 25; i += 1) {
  T[i] = X64Word.create();
}

/**
 * SHA-3 hash algorithm.
 */
class SHA3Algo extends Hasher {
  constructor(cfg) {
    /**
     * Configuration options.
     *
     * @property {number} outputLength
     *   The desired number of bits in the output hash.
     *   Only values permitted are: 224, 256, 384, 512.
     *   Default: 512
     */
    super(Object.assign(
      { outputLength: 512 },
      cfg,
    ));
  }

  _doReset() {
    this._state = [];
    const state = this._state;
    for (let i = 0; i < 25; i += 1) {
      state[i] = new X64Word();
    }

    this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
  }

  _doProcessBlock(M, offset) {
    // Shortcuts
    const state = this._state;
    const nBlockSizeLanes = this.blockSize / 2;

    // Absorb
    for (let i = 0; i < nBlockSizeLanes; i += 1) {
      // Shortcuts
      let M2i = M[offset + 2 * i];
      let M2i1 = M[offset + 2 * i + 1];

      // Swap endian
      M2i = (((M2i << 8) | (M2i >>> 24)) & 0x00ff00ff)
        | (((M2i << 24) | (M2i >>> 8)) & 0xff00ff00);
      M2i1 = (((M2i1 << 8) | (M2i1 >>> 24)) & 0x00ff00ff)
        | (((M2i1 << 24) | (M2i1 >>> 8)) & 0xff00ff00);

      // Absorb message into state
      const lane = state[i];
      lane.high ^= M2i1;
      lane.low ^= M2i;
    }

    // Rounds
    for (let round = 0; round < 24; round += 1) {
      // Theta
      for (let x = 0; x < 5; x += 1) {
        // Mix column lanes
        let tMsw = 0;
        let tLsw = 0;
        for (let y = 0; y < 5; y += 1) {
          const lane = state[x + 5 * y];
          tMsw ^= lane.high;
          tLsw ^= lane.low;
        }

        // Temporary values
        const Tx = T[x];
        Tx.high = tMsw;
        Tx.low = tLsw;
      }
      for (let x = 0; x < 5; x += 1) {
        // Shortcuts
        const Tx4 = T[(x + 4) % 5];
        const Tx1 = T[(x + 1) % 5];
        const Tx1Msw = Tx1.high;
        const Tx1Lsw = Tx1.low;

        // Mix surrounding columns
        const tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
        const tLsw = Tx4.low ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
        for (let y = 0; y < 5; y += 1) {
          const lane = state[x + 5 * y];
          lane.high ^= tMsw;
          lane.low ^= tLsw;
        }
      }

      // Rho Pi
      for (let laneIndex = 1; laneIndex < 25; laneIndex += 1) {
        let tMsw;
        let tLsw;

        // Shortcuts
        const lane = state[laneIndex];
        const laneMsw = lane.high;
        const laneLsw = lane.low;
        const rhoOffset = RHO_OFFSETS[laneIndex];

        // Rotate lanes
        if (rhoOffset < 32) {
          tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
          tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
        } else /* if (rhoOffset >= 32) */ {
          tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
          tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
        }

        // Transpose lanes
        const TPiLane = T[PI_INDEXES[laneIndex]];
        TPiLane.high = tMsw;
        TPiLane.low = tLsw;
      }

      // Rho pi at x = y = 0
      const T0 = T[0];
      const state0 = state[0];
      T0.high = state0.high;
      T0.low = state0.low;

      // Chi
      for (let x = 0; x < 5; x += 1) {
        for (let y = 0; y < 5; y += 1) {
          // Shortcuts
          const laneIndex = x + 5 * y;
          const lane = state[laneIndex];
          const TLane = T[laneIndex];
          const Tx1Lane = T[((x + 1) % 5) + 5 * y];
          const Tx2Lane = T[((x + 2) % 5) + 5 * y];

          // Mix rows
          lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
          lane.low = TLane.low ^ (~Tx1Lane.low & Tx2Lane.low);
        }
      }

      // Iota
      const lane = state[0];
      const roundConstant = ROUND_CONSTANTS[round];
      lane.high ^= roundConstant.high;
      lane.low ^= roundConstant.low;
    }
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;
    const nBitsLeft = data.sigBytes * 8;
    const blockSizeBits = this.blockSize * 32;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - (nBitsLeft % 32));
    dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
    data.sigBytes = dataWords.length * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const state = this._state;
    const outputLengthBytes = this.cfg.outputLength / 8;
    const outputLengthLanes = outputLengthBytes / 8;

    // Squeeze
    const hashWords = [];
    for (let i = 0; i < outputLengthLanes; i += 1) {
      // Shortcuts
      const lane = state[i];
      let laneMsw = lane.high;
      let laneLsw = lane.low;

      // Swap endian
      laneMsw = (((laneMsw << 8) | (laneMsw >>> 24)) & 0x00ff00ff)
        | (((laneMsw << 24) | (laneMsw >>> 8)) & 0xff00ff00);
      laneLsw = (((laneLsw << 8) | (laneLsw >>> 24)) & 0x00ff00ff)
        | (((laneLsw << 24) | (laneLsw >>> 8)) & 0xff00ff00);

      // Squeeze state to retrieve hash
      hashWords.push(laneLsw);
      hashWords.push(laneMsw);
    }

    // Return final computed hash
    return new WordArray(hashWords, outputLengthBytes);
  }

  clone() {
    const clone = super.clone.call(this);

    clone._state = this._state.slice(0);
    const state = clone._state;
    for (let i = 0; i < 25; i += 1) {
      state[i] = state[i].clone();
    }

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.SHA3('message');
 *     var hash = CryptoJS.SHA3(wordArray);
 */
const SHA3 = Hasher._createHelper(SHA3Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacSHA3(message, key);
 */
const HmacSHA3 = Hasher._createHmacHelper(SHA3Algo);

/** @preserve
(c) 2012 by Cédric Mesnil. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice, this list of
    conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice, this list
    of conditions and the following disclaimer in the documentation and/or other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Constants table
const _zl = WordArray.create([
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]);
const _zr = WordArray.create([
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]);
const _sl = WordArray.create([
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]);
const _sr = WordArray.create([
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]);

const _hl = WordArray.create([0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
const _hr = WordArray.create([0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

const f1 = (x, y, z) => (x) ^ (y) ^ (z);

const f2 = (x, y, z) => ((x) & (y)) | ((~x) & (z));

const f3 = (x, y, z) => ((x) | (~(y))) ^ (z);

const f4 = (x, y, z) => ((x) & (z)) | ((y) & (~(z)));

const f5 = (x, y, z) => (x) ^ ((y) | (~(z)));

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/**
 * RIPEMD160 hash algorithm.
 */
class RIPEMD160Algo extends Hasher {
  _doReset() {
    this._hash = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
  }

  _doProcessBlock(M, offset) {
    const _M = M;

    // Swap endian
    for (let i = 0; i < 16; i += 1) {
      // Shortcuts
      const offset_i = offset + i;
      const M_offset_i = _M[offset_i];

      // Swap
      _M[offset_i] = (
        (((M_offset_i << 8) | (M_offset_i >>> 24)) & 0x00ff00ff)
          | (((M_offset_i << 24) | (M_offset_i >>> 8)) & 0xff00ff00)
      );
    }
    // Shortcut
    const H = this._hash.words;
    const hl = _hl.words;
    const hr = _hr.words;
    const zl = _zl.words;
    const zr = _zr.words;
    const sl = _sl.words;
    const sr = _sr.words;

    // Working variables
    let al = H[0];
    let bl = H[1];
    let cl = H[2];
    let dl = H[3];
    let el = H[4];
    let ar = H[0];
    let br = H[1];
    let cr = H[2];
    let dr = H[3];
    let er = H[4];

    // Computation
    let t;
    for (let i = 0; i < 80; i += 1) {
      t = (al + _M[offset + zl[i]]) | 0;
      if (i < 16) {
        t += f1(bl, cl, dl) + hl[0];
      } else if (i < 32) {
        t += f2(bl, cl, dl) + hl[1];
      } else if (i < 48) {
        t += f3(bl, cl, dl) + hl[2];
      } else if (i < 64) {
        t += f4(bl, cl, dl) + hl[3];
      } else { // if (i<80) {
        t += f5(bl, cl, dl) + hl[4];
      }
      t |= 0;
      t = rotl(t, sl[i]);
      t = (t + el) | 0;
      al = el;
      el = dl;
      dl = rotl(cl, 10);
      cl = bl;
      bl = t;

      t = (ar + _M[offset + zr[i]]) | 0;
      if (i < 16) {
        t += f5(br, cr, dr) + hr[0];
      } else if (i < 32) {
        t += f4(br, cr, dr) + hr[1];
      } else if (i < 48) {
        t += f3(br, cr, dr) + hr[2];
      } else if (i < 64) {
        t += f2(br, cr, dr) + hr[3];
      } else { // if (i<80) {
        t += f1(br, cr, dr) + hr[4];
      }
      t |= 0;
      t = rotl(t, sr[i]);
      t = (t + er) | 0;
      ar = er;
      er = dr;
      dr = rotl(cr, 10);
      cr = br;
      br = t;
    }
    // Intermediate hash value
    t = (H[1] + cl + dr) | 0;
    H[1] = (H[2] + dl + er) | 0;
    H[2] = (H[3] + el + ar) | 0;
    H[3] = (H[4] + al + br) | 0;
    H[4] = (H[0] + bl + cr) | 0;
    H[0] = t;
  }

  _doFinalize() {
    // Shortcuts
    const data = this._data;
    const dataWords = data.words;

    const nBitsTotal = this._nDataBytes * 8;
    const nBitsLeft = data.sigBytes * 8;

    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - (nBitsLeft % 32));
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
      (((nBitsTotal << 8) | (nBitsTotal >>> 24)) & 0x00ff00ff)
        | (((nBitsTotal << 24) | (nBitsTotal >>> 8)) & 0xff00ff00)
    );
    data.sigBytes = (dataWords.length + 1) * 4;

    // Hash final blocks
    this._process();

    // Shortcuts
    const hash = this._hash;
    const H = hash.words;

    // Swap endian
    for (let i = 0; i < 5; i += 1) {
      // Shortcut
      const H_i = H[i];

      // Swap
      H[i] = (((H_i << 8) | (H_i >>> 24)) & 0x00ff00ff)
        | (((H_i << 24) | (H_i >>> 8)) & 0xff00ff00);
    }

    // Return final computed hash
    return hash;
  }

  clone() {
    const clone = super.clone.call(this);
    clone._hash = this._hash.clone();

    return clone;
  }
}

/**
 * Shortcut function to the hasher's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 *
 * @return {WordArray} The hash.
 *
 * @static
 *
 * @example
 *
 *     var hash = CryptoJS.RIPEMD160('message');
 *     var hash = CryptoJS.RIPEMD160(wordArray);
 */
const RIPEMD160 = Hasher._createHelper(RIPEMD160Algo);

/**
 * Shortcut function to the HMAC's object interface.
 *
 * @param {WordArray|string} message The message to hash.
 * @param {WordArray|string} key The secret key.
 *
 * @return {WordArray} The HMAC.
 *
 * @static
 *
 * @example
 *
 *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
 */
const HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160Algo);

/**
 * Password-Based Key Derivation Function 2 algorithm.
 */
class PBKDF2Algo extends Base {
  /**
   * Initializes a newly created key derivation function.
   *
   * @param {Object} cfg (Optional) The configuration options to use for the derivation.
   *
   * @example
   *
   *     const kdf = CryptoJS.algo.PBKDF2.create();
   *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
   *     const kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
   */
  constructor(cfg) {
    super();

    /**
     * Configuration options.
     *
     * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
     * @property {Hasher} hasher The hasher to use. Default: SHA1
     * @property {number} iterations The number of iterations to perform. Default: 1
     */
    this.cfg = Object.assign(
      new Base(),
      {
        keySize: 128 / 32,
        hasher: SHA1Algo,
        iterations: 1,
      },
      cfg,
    );
  }

  /**
   * Computes the Password-Based Key Derivation Function 2.
   *
   * @param {WordArray|string} password The password.
   * @param {WordArray|string} salt A salt.
   *
   * @return {WordArray} The derived key.
   *
   * @example
   *
   *     const key = kdf.compute(password, salt);
   */
  compute(password, salt) {
    // Shortcut
    const { cfg } = this;

    // Init HMAC
    const hmac = HMAC.create(cfg.hasher, password);

    // Initial values
    const derivedKey = WordArray.create();
    const blockIndex = WordArray.create([0x00000001]);

    // Shortcuts
    const derivedKeyWords = derivedKey.words;
    const blockIndexWords = blockIndex.words;
    const { keySize, iterations } = cfg;

    // Generate key
    while (derivedKeyWords.length < keySize) {
      const block = hmac.update(salt).finalize(blockIndex);
      hmac.reset();

      // Shortcuts
      const blockWords = block.words;
      const blockWordsLength = blockWords.length;

      // Iterations
      let intermediate = block;
      for (let i = 1; i < iterations; i += 1) {
        intermediate = hmac.finalize(intermediate);
        hmac.reset();

        // Shortcut
        const intermediateWords = intermediate.words;

        // XOR intermediate with block
        for (let j = 0; j < blockWordsLength; j += 1) {
          blockWords[j] ^= intermediateWords[j];
        }
      }

      derivedKey.concat(block);
      blockIndexWords[0] += 1;
    }
    derivedKey.sigBytes = keySize * 4;

    return derivedKey;
  }
}

/**
 * Computes the Password-Based Key Derivation Function 2.
 *
 * @param {WordArray|string} password The password.
 * @param {WordArray|string} salt A salt.
 * @param {Object} cfg (Optional) The configuration options to use for this computation.
 *
 * @return {WordArray} The derived key.
 *
 * @static
 *
 * @example
 *
 *     var key = CryptoJS.PBKDF2(password, salt);
 *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
 *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
 */
const PBKDF2 = (password, salt, cfg) => PBKDF2Algo.create(cfg).compute(password, salt);

// Lookup tables
const _SBOX = [];
const INV_SBOX = [];
const _SUB_MIX_0 = [];
const _SUB_MIX_1 = [];
const _SUB_MIX_2 = [];
const _SUB_MIX_3 = [];
const INV_SUB_MIX_0 = [];
const INV_SUB_MIX_1 = [];
const INV_SUB_MIX_2 = [];
const INV_SUB_MIX_3 = [];

// Compute lookup tables

// Compute double table
const d = [];
for (let i = 0; i < 256; i += 1) {
  if (i < 128) {
    d[i] = i << 1;
  } else {
    d[i] = (i << 1) ^ 0x11b;
  }
}

// Walk GF(2^8)
let x = 0;
let xi = 0;
for (let i = 0; i < 256; i += 1) {
  // Compute sbox
  let sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
  sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
  _SBOX[x] = sx;
  INV_SBOX[sx] = x;

  // Compute multiplication
  const x2 = d[x];
  const x4 = d[x2];
  const x8 = d[x4];

  // Compute sub bytes, mix columns tables
  let t = (d[sx] * 0x101) ^ (sx * 0x1010100);
  _SUB_MIX_0[x] = (t << 24) | (t >>> 8);
  _SUB_MIX_1[x] = (t << 16) | (t >>> 16);
  _SUB_MIX_2[x] = (t << 8) | (t >>> 24);
  _SUB_MIX_3[x] = t;

  // Compute inv sub bytes, inv mix columns tables
  t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
  INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
  INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
  INV_SUB_MIX_2[sx] = (t << 8) | (t >>> 24);
  INV_SUB_MIX_3[sx] = t;

  // Compute next counter
  if (!x) {
    xi = 1;
    x = xi;
  } else {
    x = x2 ^ d[d[d[x8 ^ x2]]];
    xi ^= d[d[xi]];
  }
}

// Precomputed Rcon lookup
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/**
 * AES block cipher algorithm.
 */
class AESAlgo extends BlockCipher {
  _doReset() {
    let t;

    // Skip reset of nRounds has been set before and key did not change
    if (this._nRounds && this._keyPriorReset === this._key) {
      return;
    }

    // Shortcuts
    this._keyPriorReset = this._key;
    const key = this._keyPriorReset;
    const keyWords = key.words;
    const keySize = key.sigBytes / 4;

    // Compute number of rounds
    this._nRounds = keySize + 6;
    const nRounds = this._nRounds;

    // Compute number of key schedule rows
    const ksRows = (nRounds + 1) * 4;

    // Compute key schedule
    this._keySchedule = [];
    const keySchedule = this._keySchedule;
    for (let ksRow = 0; ksRow < ksRows; ksRow += 1) {
      if (ksRow < keySize) {
        keySchedule[ksRow] = keyWords[ksRow];
      } else {
        t = keySchedule[ksRow - 1];

        if (!(ksRow % keySize)) {
          // Rot word
          t = (t << 8) | (t >>> 24);

          // Sub word
          t = (_SBOX[t >>> 24] << 24)
            | (_SBOX[(t >>> 16) & 0xff] << 16)
            | (_SBOX[(t >>> 8) & 0xff] << 8)
            | _SBOX[t & 0xff];

          // Mix Rcon
          t ^= RCON[(ksRow / keySize) | 0] << 24;
        } else if (keySize > 6 && ksRow % keySize === 4) {
          // Sub word
          t = (_SBOX[t >>> 24] << 24)
            | (_SBOX[(t >>> 16) & 0xff] << 16)
            | (_SBOX[(t >>> 8) & 0xff] << 8)
            | _SBOX[t & 0xff];
        }

        keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
      }
    }

    // Compute inv key schedule
    this._invKeySchedule = [];
    const invKeySchedule = this._invKeySchedule;
    for (let invKsRow = 0; invKsRow < ksRows; invKsRow += 1) {
      const ksRow = ksRows - invKsRow;

      if (invKsRow % 4) {
        t = keySchedule[ksRow];
      } else {
        t = keySchedule[ksRow - 4];
      }

      if (invKsRow < 4 || ksRow <= 4) {
        invKeySchedule[invKsRow] = t;
      } else {
        invKeySchedule[invKsRow] = INV_SUB_MIX_0[_SBOX[t >>> 24]]
          ^ INV_SUB_MIX_1[_SBOX[(t >>> 16) & 0xff]]
          ^ INV_SUB_MIX_2[_SBOX[(t >>> 8) & 0xff]]
          ^ INV_SUB_MIX_3[_SBOX[t & 0xff]];
      }
    }
  }

  encryptBlock(M, offset) {
    this._doCryptBlock(
      M, offset, this._keySchedule, _SUB_MIX_0, _SUB_MIX_1, _SUB_MIX_2, _SUB_MIX_3, _SBOX,
    );
  }

  decryptBlock(M, offset) {
    const _M = M;

    // Swap 2nd and 4th rows
    let t = _M[offset + 1];
    _M[offset + 1] = _M[offset + 3];
    _M[offset + 3] = t;

    this._doCryptBlock(
      _M,
      offset,
      this._invKeySchedule,
      INV_SUB_MIX_0,
      INV_SUB_MIX_1,
      INV_SUB_MIX_2,
      INV_SUB_MIX_3,
      INV_SBOX,
    );

    // Inv swap 2nd and 4th rows
    t = _M[offset + 1];
    _M[offset + 1] = _M[offset + 3];
    _M[offset + 3] = t;
  }

  _doCryptBlock(M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
    const _M = M;

    // Shortcut
    const nRounds = this._nRounds;

    // Get input, add round key
    let s0 = _M[offset] ^ keySchedule[0];
    let s1 = _M[offset + 1] ^ keySchedule[1];
    let s2 = _M[offset + 2] ^ keySchedule[2];
    let s3 = _M[offset + 3] ^ keySchedule[3];

    // Key schedule row counter
    let ksRow = 4;

    // Rounds
    for (let round = 1; round < nRounds; round += 1) {
      // Shift rows, sub bytes, mix columns, add round key
      const t0 = SUB_MIX_0[s0 >>> 24]
        ^ SUB_MIX_1[(s1 >>> 16) & 0xff]
        ^ SUB_MIX_2[(s2 >>> 8) & 0xff]
        ^ SUB_MIX_3[s3 & 0xff]
        ^ keySchedule[ksRow];
      ksRow += 1;
      const t1 = SUB_MIX_0[s1 >>> 24]
        ^ SUB_MIX_1[(s2 >>> 16) & 0xff]
        ^ SUB_MIX_2[(s3 >>> 8) & 0xff]
        ^ SUB_MIX_3[s0 & 0xff]
        ^ keySchedule[ksRow];
      ksRow += 1;
      const t2 = SUB_MIX_0[s2 >>> 24]
        ^ SUB_MIX_1[(s3 >>> 16) & 0xff]
        ^ SUB_MIX_2[(s0 >>> 8) & 0xff]
        ^ SUB_MIX_3[s1 & 0xff]
        ^ keySchedule[ksRow];
      ksRow += 1;
      const t3 = SUB_MIX_0[s3 >>> 24]
        ^ SUB_MIX_1[(s0 >>> 16) & 0xff]
        ^ SUB_MIX_2[(s1 >>> 8) & 0xff]
        ^ SUB_MIX_3[s2 & 0xff]
        ^ keySchedule[ksRow];
      ksRow += 1;

      // Update state
      s0 = t0;
      s1 = t1;
      s2 = t2;
      s3 = t3;
    }

    // Shift rows, sub bytes, add round key
    const t0 = (
      (SBOX[s0 >>> 24] << 24)
        | (SBOX[(s1 >>> 16) & 0xff] << 16)
        | (SBOX[(s2 >>> 8) & 0xff] << 8)
        | SBOX[s3 & 0xff]
    ) ^ keySchedule[ksRow];
    ksRow += 1;
    const t1 = (
      (SBOX[s1 >>> 24] << 24)
        | (SBOX[(s2 >>> 16) & 0xff] << 16)
        | (SBOX[(s3 >>> 8) & 0xff] << 8)
        | SBOX[s0 & 0xff]
    ) ^ keySchedule[ksRow];
    ksRow += 1;
    const t2 = (
      (SBOX[s2 >>> 24] << 24)
        | (SBOX[(s3 >>> 16) & 0xff] << 16)
        | (SBOX[(s0 >>> 8) & 0xff] << 8)
        | SBOX[s1 & 0xff]
    ) ^ keySchedule[ksRow];
    ksRow += 1;
    const t3 = (
      (SBOX[s3 >>> 24] << 24)
        | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]
    ) ^ keySchedule[ksRow];
    ksRow += 1;

    // Set output
    _M[offset] = t0;
    _M[offset + 1] = t1;
    _M[offset + 2] = t2;
    _M[offset + 3] = t3;
  }
}
AESAlgo.keySize = 256 / 32;

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
 */
const AES = BlockCipher._createHelper(AESAlgo);

// Permuted Choice 1 constants
const PC1 = [
  57, 49, 41, 33, 25, 17, 9, 1,
  58, 50, 42, 34, 26, 18, 10, 2,
  59, 51, 43, 35, 27, 19, 11, 3,
  60, 52, 44, 36, 63, 55, 47, 39,
  31, 23, 15, 7, 62, 54, 46, 38,
  30, 22, 14, 6, 61, 53, 45, 37,
  29, 21, 13, 5, 28, 20, 12, 4,
];

// Permuted Choice 2 constants
const PC2 = [
  14, 17, 11, 24, 1, 5,
  3, 28, 15, 6, 21, 10,
  23, 19, 12, 4, 26, 8,
  16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
];

// Cumulative bit shift constants
const BIT_SHIFTS = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

// SBOXes and round permutation constants
const SBOX_P = [
  {
    0x0: 0x808200,
    0x10000000: 0x8000,
    0x20000000: 0x808002,
    0x30000000: 0x2,
    0x40000000: 0x200,
    0x50000000: 0x808202,
    0x60000000: 0x800202,
    0x70000000: 0x800000,
    0x80000000: 0x202,
    0x90000000: 0x800200,
    0xa0000000: 0x8200,
    0xb0000000: 0x808000,
    0xc0000000: 0x8002,
    0xd0000000: 0x800002,
    0xe0000000: 0x0,
    0xf0000000: 0x8202,
    0x8000000: 0x0,
    0x18000000: 0x808202,
    0x28000000: 0x8202,
    0x38000000: 0x8000,
    0x48000000: 0x808200,
    0x58000000: 0x200,
    0x68000000: 0x808002,
    0x78000000: 0x2,
    0x88000000: 0x800200,
    0x98000000: 0x8200,
    0xa8000000: 0x808000,
    0xb8000000: 0x800202,
    0xc8000000: 0x800002,
    0xd8000000: 0x8002,
    0xe8000000: 0x202,
    0xf8000000: 0x800000,
    0x1: 0x8000,
    0x10000001: 0x2,
    0x20000001: 0x808200,
    0x30000001: 0x800000,
    0x40000001: 0x808002,
    0x50000001: 0x8200,
    0x60000001: 0x200,
    0x70000001: 0x800202,
    0x80000001: 0x808202,
    0x90000001: 0x808000,
    0xa0000001: 0x800002,
    0xb0000001: 0x8202,
    0xc0000001: 0x202,
    0xd0000001: 0x800200,
    0xe0000001: 0x8002,
    0xf0000001: 0x0,
    0x8000001: 0x808202,
    0x18000001: 0x808000,
    0x28000001: 0x800000,
    0x38000001: 0x200,
    0x48000001: 0x8000,
    0x58000001: 0x800002,
    0x68000001: 0x2,
    0x78000001: 0x8202,
    0x88000001: 0x8002,
    0x98000001: 0x800202,
    0xa8000001: 0x202,
    0xb8000001: 0x808200,
    0xc8000001: 0x800200,
    0xd8000001: 0x0,
    0xe8000001: 0x8200,
    0xf8000001: 0x808002,
  },
  {
    0x0: 0x40084010,
    0x1000000: 0x4000,
    0x2000000: 0x80000,
    0x3000000: 0x40080010,
    0x4000000: 0x40000010,
    0x5000000: 0x40084000,
    0x6000000: 0x40004000,
    0x7000000: 0x10,
    0x8000000: 0x84000,
    0x9000000: 0x40004010,
    0xa000000: 0x40000000,
    0xb000000: 0x84010,
    0xc000000: 0x80010,
    0xd000000: 0x0,
    0xe000000: 0x4010,
    0xf000000: 0x40080000,
    0x800000: 0x40004000,
    0x1800000: 0x84010,
    0x2800000: 0x10,
    0x3800000: 0x40004010,
    0x4800000: 0x40084010,
    0x5800000: 0x40000000,
    0x6800000: 0x80000,
    0x7800000: 0x40080010,
    0x8800000: 0x80010,
    0x9800000: 0x0,
    0xa800000: 0x4000,
    0xb800000: 0x40080000,
    0xc800000: 0x40000010,
    0xd800000: 0x84000,
    0xe800000: 0x40084000,
    0xf800000: 0x4010,
    0x10000000: 0x0,
    0x11000000: 0x40080010,
    0x12000000: 0x40004010,
    0x13000000: 0x40084000,
    0x14000000: 0x40080000,
    0x15000000: 0x10,
    0x16000000: 0x84010,
    0x17000000: 0x4000,
    0x18000000: 0x4010,
    0x19000000: 0x80000,
    0x1a000000: 0x80010,
    0x1b000000: 0x40000010,
    0x1c000000: 0x84000,
    0x1d000000: 0x40004000,
    0x1e000000: 0x40000000,
    0x1f000000: 0x40084010,
    0x10800000: 0x84010,
    0x11800000: 0x80000,
    0x12800000: 0x40080000,
    0x13800000: 0x4000,
    0x14800000: 0x40004000,
    0x15800000: 0x40084010,
    0x16800000: 0x10,
    0x17800000: 0x40000000,
    0x18800000: 0x40084000,
    0x19800000: 0x40000010,
    0x1a800000: 0x40004010,
    0x1b800000: 0x80010,
    0x1c800000: 0x0,
    0x1d800000: 0x4010,
    0x1e800000: 0x40080010,
    0x1f800000: 0x84000,
  },
  {
    0x0: 0x104,
    0x100000: 0x0,
    0x200000: 0x4000100,
    0x300000: 0x10104,
    0x400000: 0x10004,
    0x500000: 0x4000004,
    0x600000: 0x4010104,
    0x700000: 0x4010000,
    0x800000: 0x4000000,
    0x900000: 0x4010100,
    0xa00000: 0x10100,
    0xb00000: 0x4010004,
    0xc00000: 0x4000104,
    0xd00000: 0x10000,
    0xe00000: 0x4,
    0xf00000: 0x100,
    0x80000: 0x4010100,
    0x180000: 0x4010004,
    0x280000: 0x0,
    0x380000: 0x4000100,
    0x480000: 0x4000004,
    0x580000: 0x10000,
    0x680000: 0x10004,
    0x780000: 0x104,
    0x880000: 0x4,
    0x980000: 0x100,
    0xa80000: 0x4010000,
    0xb80000: 0x10104,
    0xc80000: 0x10100,
    0xd80000: 0x4000104,
    0xe80000: 0x4010104,
    0xf80000: 0x4000000,
    0x1000000: 0x4010100,
    0x1100000: 0x10004,
    0x1200000: 0x10000,
    0x1300000: 0x4000100,
    0x1400000: 0x100,
    0x1500000: 0x4010104,
    0x1600000: 0x4000004,
    0x1700000: 0x0,
    0x1800000: 0x4000104,
    0x1900000: 0x4000000,
    0x1a00000: 0x4,
    0x1b00000: 0x10100,
    0x1c00000: 0x4010000,
    0x1d00000: 0x104,
    0x1e00000: 0x10104,
    0x1f00000: 0x4010004,
    0x1080000: 0x4000000,
    0x1180000: 0x104,
    0x1280000: 0x4010100,
    0x1380000: 0x0,
    0x1480000: 0x10004,
    0x1580000: 0x4000100,
    0x1680000: 0x100,
    0x1780000: 0x4010004,
    0x1880000: 0x10000,
    0x1980000: 0x4010104,
    0x1a80000: 0x10104,
    0x1b80000: 0x4000004,
    0x1c80000: 0x4000104,
    0x1d80000: 0x4010000,
    0x1e80000: 0x4,
    0x1f80000: 0x10100,
  },
  {
    0x0: 0x80401000,
    0x10000: 0x80001040,
    0x20000: 0x401040,
    0x30000: 0x80400000,
    0x40000: 0x0,
    0x50000: 0x401000,
    0x60000: 0x80000040,
    0x70000: 0x400040,
    0x80000: 0x80000000,
    0x90000: 0x400000,
    0xa0000: 0x40,
    0xb0000: 0x80001000,
    0xc0000: 0x80400040,
    0xd0000: 0x1040,
    0xe0000: 0x1000,
    0xf0000: 0x80401040,
    0x8000: 0x80001040,
    0x18000: 0x40,
    0x28000: 0x80400040,
    0x38000: 0x80001000,
    0x48000: 0x401000,
    0x58000: 0x80401040,
    0x68000: 0x0,
    0x78000: 0x80400000,
    0x88000: 0x1000,
    0x98000: 0x80401000,
    0xa8000: 0x400000,
    0xb8000: 0x1040,
    0xc8000: 0x80000000,
    0xd8000: 0x400040,
    0xe8000: 0x401040,
    0xf8000: 0x80000040,
    0x100000: 0x400040,
    0x110000: 0x401000,
    0x120000: 0x80000040,
    0x130000: 0x0,
    0x140000: 0x1040,
    0x150000: 0x80400040,
    0x160000: 0x80401000,
    0x170000: 0x80001040,
    0x180000: 0x80401040,
    0x190000: 0x80000000,
    0x1a0000: 0x80400000,
    0x1b0000: 0x401040,
    0x1c0000: 0x80001000,
    0x1d0000: 0x400000,
    0x1e0000: 0x40,
    0x1f0000: 0x1000,
    0x108000: 0x80400000,
    0x118000: 0x80401040,
    0x128000: 0x0,
    0x138000: 0x401000,
    0x148000: 0x400040,
    0x158000: 0x80000000,
    0x168000: 0x80001040,
    0x178000: 0x40,
    0x188000: 0x80000040,
    0x198000: 0x1000,
    0x1a8000: 0x80001000,
    0x1b8000: 0x80400040,
    0x1c8000: 0x1040,
    0x1d8000: 0x80401000,
    0x1e8000: 0x400000,
    0x1f8000: 0x401040,
  },
  {
    0x0: 0x80,
    0x1000: 0x1040000,
    0x2000: 0x40000,
    0x3000: 0x20000000,
    0x4000: 0x20040080,
    0x5000: 0x1000080,
    0x6000: 0x21000080,
    0x7000: 0x40080,
    0x8000: 0x1000000,
    0x9000: 0x20040000,
    0xa000: 0x20000080,
    0xb000: 0x21040080,
    0xc000: 0x21040000,
    0xd000: 0x0,
    0xe000: 0x1040080,
    0xf000: 0x21000000,
    0x800: 0x1040080,
    0x1800: 0x21000080,
    0x2800: 0x80,
    0x3800: 0x1040000,
    0x4800: 0x40000,
    0x5800: 0x20040080,
    0x6800: 0x21040000,
    0x7800: 0x20000000,
    0x8800: 0x20040000,
    0x9800: 0x0,
    0xa800: 0x21040080,
    0xb800: 0x1000080,
    0xc800: 0x20000080,
    0xd800: 0x21000000,
    0xe800: 0x1000000,
    0xf800: 0x40080,
    0x10000: 0x40000,
    0x11000: 0x80,
    0x12000: 0x20000000,
    0x13000: 0x21000080,
    0x14000: 0x1000080,
    0x15000: 0x21040000,
    0x16000: 0x20040080,
    0x17000: 0x1000000,
    0x18000: 0x21040080,
    0x19000: 0x21000000,
    0x1a000: 0x1040000,
    0x1b000: 0x20040000,
    0x1c000: 0x40080,
    0x1d000: 0x20000080,
    0x1e000: 0x0,
    0x1f000: 0x1040080,
    0x10800: 0x21000080,
    0x11800: 0x1000000,
    0x12800: 0x1040000,
    0x13800: 0x20040080,
    0x14800: 0x20000000,
    0x15800: 0x1040080,
    0x16800: 0x80,
    0x17800: 0x21040000,
    0x18800: 0x40080,
    0x19800: 0x21040080,
    0x1a800: 0x0,
    0x1b800: 0x21000000,
    0x1c800: 0x1000080,
    0x1d800: 0x40000,
    0x1e800: 0x20040000,
    0x1f800: 0x20000080,
  },
  {
    0x0: 0x10000008,
    0x100: 0x2000,
    0x200: 0x10200000,
    0x300: 0x10202008,
    0x400: 0x10002000,
    0x500: 0x200000,
    0x600: 0x200008,
    0x700: 0x10000000,
    0x800: 0x0,
    0x900: 0x10002008,
    0xa00: 0x202000,
    0xb00: 0x8,
    0xc00: 0x10200008,
    0xd00: 0x202008,
    0xe00: 0x2008,
    0xf00: 0x10202000,
    0x80: 0x10200000,
    0x180: 0x10202008,
    0x280: 0x8,
    0x380: 0x200000,
    0x480: 0x202008,
    0x580: 0x10000008,
    0x680: 0x10002000,
    0x780: 0x2008,
    0x880: 0x200008,
    0x980: 0x2000,
    0xa80: 0x10002008,
    0xb80: 0x10200008,
    0xc80: 0x0,
    0xd80: 0x10202000,
    0xe80: 0x202000,
    0xf80: 0x10000000,
    0x1000: 0x10002000,
    0x1100: 0x10200008,
    0x1200: 0x10202008,
    0x1300: 0x2008,
    0x1400: 0x200000,
    0x1500: 0x10000000,
    0x1600: 0x10000008,
    0x1700: 0x202000,
    0x1800: 0x202008,
    0x1900: 0x0,
    0x1a00: 0x8,
    0x1b00: 0x10200000,
    0x1c00: 0x2000,
    0x1d00: 0x10002008,
    0x1e00: 0x10202000,
    0x1f00: 0x200008,
    0x1080: 0x8,
    0x1180: 0x202000,
    0x1280: 0x200000,
    0x1380: 0x10000008,
    0x1480: 0x10002000,
    0x1580: 0x2008,
    0x1680: 0x10202008,
    0x1780: 0x10200000,
    0x1880: 0x10202000,
    0x1980: 0x10200008,
    0x1a80: 0x2000,
    0x1b80: 0x202008,
    0x1c80: 0x200008,
    0x1d80: 0x0,
    0x1e80: 0x10000000,
    0x1f80: 0x10002008,
  },
  {
    0x0: 0x100000,
    0x10: 0x2000401,
    0x20: 0x400,
    0x30: 0x100401,
    0x40: 0x2100401,
    0x50: 0x0,
    0x60: 0x1,
    0x70: 0x2100001,
    0x80: 0x2000400,
    0x90: 0x100001,
    0xa0: 0x2000001,
    0xb0: 0x2100400,
    0xc0: 0x2100000,
    0xd0: 0x401,
    0xe0: 0x100400,
    0xf0: 0x2000000,
    0x8: 0x2100001,
    0x18: 0x0,
    0x28: 0x2000401,
    0x38: 0x2100400,
    0x48: 0x100000,
    0x58: 0x2000001,
    0x68: 0x2000000,
    0x78: 0x401,
    0x88: 0x100401,
    0x98: 0x2000400,
    0xa8: 0x2100000,
    0xb8: 0x100001,
    0xc8: 0x400,
    0xd8: 0x2100401,
    0xe8: 0x1,
    0xf8: 0x100400,
    0x100: 0x2000000,
    0x110: 0x100000,
    0x120: 0x2000401,
    0x130: 0x2100001,
    0x140: 0x100001,
    0x150: 0x2000400,
    0x160: 0x2100400,
    0x170: 0x100401,
    0x180: 0x401,
    0x190: 0x2100401,
    0x1a0: 0x100400,
    0x1b0: 0x1,
    0x1c0: 0x0,
    0x1d0: 0x2100000,
    0x1e0: 0x2000001,
    0x1f0: 0x400,
    0x108: 0x100400,
    0x118: 0x2000401,
    0x128: 0x2100001,
    0x138: 0x1,
    0x148: 0x2000000,
    0x158: 0x100000,
    0x168: 0x401,
    0x178: 0x2100400,
    0x188: 0x2000001,
    0x198: 0x2100000,
    0x1a8: 0x0,
    0x1b8: 0x2100401,
    0x1c8: 0x100401,
    0x1d8: 0x400,
    0x1e8: 0x2000400,
    0x1f8: 0x100001,
  },
  {
    0x0: 0x8000820,
    0x1: 0x20000,
    0x2: 0x8000000,
    0x3: 0x20,
    0x4: 0x20020,
    0x5: 0x8020820,
    0x6: 0x8020800,
    0x7: 0x800,
    0x8: 0x8020000,
    0x9: 0x8000800,
    0xa: 0x20800,
    0xb: 0x8020020,
    0xc: 0x820,
    0xd: 0x0,
    0xe: 0x8000020,
    0xf: 0x20820,
    0x80000000: 0x800,
    0x80000001: 0x8020820,
    0x80000002: 0x8000820,
    0x80000003: 0x8000000,
    0x80000004: 0x8020000,
    0x80000005: 0x20800,
    0x80000006: 0x20820,
    0x80000007: 0x20,
    0x80000008: 0x8000020,
    0x80000009: 0x820,
    0x8000000a: 0x20020,
    0x8000000b: 0x8020800,
    0x8000000c: 0x0,
    0x8000000d: 0x8020020,
    0x8000000e: 0x8000800,
    0x8000000f: 0x20000,
    0x10: 0x20820,
    0x11: 0x8020800,
    0x12: 0x20,
    0x13: 0x800,
    0x14: 0x8000800,
    0x15: 0x8000020,
    0x16: 0x8020020,
    0x17: 0x20000,
    0x18: 0x0,
    0x19: 0x20020,
    0x1a: 0x8020000,
    0x1b: 0x8000820,
    0x1c: 0x8020820,
    0x1d: 0x20800,
    0x1e: 0x820,
    0x1f: 0x8000000,
    0x80000010: 0x20000,
    0x80000011: 0x800,
    0x80000012: 0x8020020,
    0x80000013: 0x20820,
    0x80000014: 0x20,
    0x80000015: 0x8020000,
    0x80000016: 0x8000000,
    0x80000017: 0x8000820,
    0x80000018: 0x8020820,
    0x80000019: 0x8000020,
    0x8000001a: 0x8000800,
    0x8000001b: 0x0,
    0x8000001c: 0x20800,
    0x8000001d: 0x820,
    0x8000001e: 0x20020,
    0x8000001f: 0x8020800,
  },
];

// Masks that select the SBOX input
const SBOX_MASK = [
  0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
  0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f,
];

// Swap bits across the left and right words
function exchangeLR(offset, mask) {
  const t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
  this._rBlock ^= t;
  this._lBlock ^= t << offset;
}

function exchangeRL(offset, mask) {
  const t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
  this._lBlock ^= t;
  this._rBlock ^= t << offset;
}

/**
 * DES block cipher algorithm.
 */
class DESAlgo extends BlockCipher {
  _doReset() {
    // Shortcuts
    const key = this._key;
    const keyWords = key.words;

    // Select 56 bits according to PC1
    const keyBits = [];
    for (let i = 0; i < 56; i += 1) {
      const keyBitPos = PC1[i] - 1;
      keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - (keyBitPos % 32))) & 1;
    }

    // Assemble 16 subkeys
    this._subKeys = [];
    const subKeys = this._subKeys;
    for (let nSubKey = 0; nSubKey < 16; nSubKey += 1) {
      // Create subkey
      subKeys[nSubKey] = [];
      const subKey = subKeys[nSubKey];

      // Shortcut
      const bitShift = BIT_SHIFTS[nSubKey];

      // Select 48 bits according to PC2
      for (let i = 0; i < 24; i += 1) {
        // Select from the left 28 key bits
        subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - (i % 6));

        // Select from the right 28 key bits
        subKey[4 + ((i / 6) | 0)]
          |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)]
          << (31 - (i % 6));
      }

      // Since each subkey is applied to an expanded 32-bit input,
      // the subkey can be broken into 8 values scaled to 32-bits,
      // which allows the key to be used without expansion
      subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
      for (let i = 1; i < 7; i += 1) {
        subKey[i] >>>= ((i - 1) * 4 + 3);
      }
      subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
    }

    // Compute inverse subkeys
    this._invSubKeys = [];
    const invSubKeys = this._invSubKeys;
    for (let i = 0; i < 16; i += 1) {
      invSubKeys[i] = subKeys[15 - i];
    }
  }

  encryptBlock(M, offset) {
    this._doCryptBlock(M, offset, this._subKeys);
  }

  decryptBlock(M, offset) {
    this._doCryptBlock(M, offset, this._invSubKeys);
  }

  _doCryptBlock(M, offset, subKeys) {
    const _M = M;

    // Get input
    this._lBlock = M[offset];
    this._rBlock = M[offset + 1];

    // Initial permutation
    exchangeLR.call(this, 4, 0x0f0f0f0f);
    exchangeLR.call(this, 16, 0x0000ffff);
    exchangeRL.call(this, 2, 0x33333333);
    exchangeRL.call(this, 8, 0x00ff00ff);
    exchangeLR.call(this, 1, 0x55555555);

    // Rounds
    for (let round = 0; round < 16; round += 1) {
      // Shortcuts
      const subKey = subKeys[round];
      const lBlock = this._lBlock;
      const rBlock = this._rBlock;

      // Feistel function
      let f = 0;
      for (let i = 0; i < 8; i += 1) {
        f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
      }
      this._lBlock = rBlock;
      this._rBlock = lBlock ^ f;
    }

    // Undo swap from last round
    const t = this._lBlock;
    this._lBlock = this._rBlock;
    this._rBlock = t;

    // Final permutation
    exchangeLR.call(this, 1, 0x55555555);
    exchangeRL.call(this, 8, 0x00ff00ff);
    exchangeRL.call(this, 2, 0x33333333);
    exchangeLR.call(this, 16, 0x0000ffff);
    exchangeLR.call(this, 4, 0x0f0f0f0f);

    // Set output
    _M[offset] = this._lBlock;
    _M[offset + 1] = this._rBlock;
  }
}
DESAlgo.keySize = 64 / 32;
DESAlgo.ivSize = 64 / 32;
DESAlgo.blockSize = 64 / 32;

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
 */
const DES = BlockCipher._createHelper(DESAlgo);

/**
 * Triple-DES block cipher algorithm.
 */
class TripleDESAlgo extends BlockCipher {
  _doReset() {
    // Shortcuts
    const key = this._key;
    const keyWords = key.words;
    // Make sure the key length is valid (64, 128 or >= 192 bit)
    if (keyWords.length !== 2 && keyWords.length !== 4 && keyWords.length < 6) {
      throw new Error('Invalid key length - 3DES requires the key length to be 64, 128, 192 or >192.');
    }

    // Extend the key according to the keying options defined in 3DES standard
    const key1 = keyWords.slice(0, 2);
    const key2 = keyWords.length < 4 ? keyWords.slice(0, 2) : keyWords.slice(2, 4);
    const key3 = keyWords.length < 6 ? keyWords.slice(0, 2) : keyWords.slice(4, 6);

    // Create DES instances
    this._des1 = DESAlgo.createEncryptor(WordArray.create(key1));
    this._des2 = DESAlgo.createEncryptor(WordArray.create(key2));
    this._des3 = DESAlgo.createEncryptor(WordArray.create(key3));
  }

  encryptBlock(M, offset) {
    this._des1.encryptBlock(M, offset);
    this._des2.decryptBlock(M, offset);
    this._des3.encryptBlock(M, offset);
  }

  decryptBlock(M, offset) {
    this._des3.decryptBlock(M, offset);
    this._des2.encryptBlock(M, offset);
    this._des1.decryptBlock(M, offset);
  }
}
TripleDESAlgo.keySize = 192 / 32;
TripleDESAlgo.ivSize = 64 / 32;
TripleDESAlgo.blockSize = 64 / 32;

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
 */
const TripleDES = BlockCipher._createHelper(TripleDESAlgo);

// Reusable objects
const S$1 = [];
const C_$1 = [];
const G$1 = [];

function nextState$1() {
  // Shortcuts
  const X = this._X;
  const C = this._C;

  // Save old counter values
  for (let i = 0; i < 8; i += 1) {
    C_$1[i] = C[i];
  }

  // Calculate new counter values
  C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
  C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_$1[0] >>> 0) ? 1 : 0)) | 0;
  C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_$1[1] >>> 0) ? 1 : 0)) | 0;
  C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_$1[2] >>> 0) ? 1 : 0)) | 0;
  C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_$1[3] >>> 0) ? 1 : 0)) | 0;
  C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_$1[4] >>> 0) ? 1 : 0)) | 0;
  C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_$1[5] >>> 0) ? 1 : 0)) | 0;
  C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_$1[6] >>> 0) ? 1 : 0)) | 0;
  this._b = (C[7] >>> 0) < (C_$1[7] >>> 0) ? 1 : 0;

  // Calculate the g-values
  for (let i = 0; i < 8; i += 1) {
    const gx = X[i] + C[i];

    // Construct high and low argument for squaring
    const ga = gx & 0xffff;
    const gb = gx >>> 16;

    // Calculate high and low result of squaring
    const gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
    const gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

    // High XOR low
    G$1[i] = gh ^ gl;
  }

  // Calculate new state values
  X[0] = (G$1[0] + ((G$1[7] << 16) | (G$1[7] >>> 16)) + ((G$1[6] << 16) | (G$1[6] >>> 16))) | 0;
  X[1] = (G$1[1] + ((G$1[0] << 8) | (G$1[0] >>> 24)) + G$1[7]) | 0;
  X[2] = (G$1[2] + ((G$1[1] << 16) | (G$1[1] >>> 16)) + ((G$1[0] << 16) | (G$1[0] >>> 16))) | 0;
  X[3] = (G$1[3] + ((G$1[2] << 8) | (G$1[2] >>> 24)) + G$1[1]) | 0;
  X[4] = (G$1[4] + ((G$1[3] << 16) | (G$1[3] >>> 16)) + ((G$1[2] << 16) | (G$1[2] >>> 16))) | 0;
  X[5] = (G$1[5] + ((G$1[4] << 8) | (G$1[4] >>> 24)) + G$1[3]) | 0;
  X[6] = (G$1[6] + ((G$1[5] << 16) | (G$1[5] >>> 16)) + ((G$1[4] << 16) | (G$1[4] >>> 16))) | 0;
  X[7] = (G$1[7] + ((G$1[6] << 8) | (G$1[6] >>> 24)) + G$1[5]) | 0;
}

/**
 * Rabbit stream cipher algorithm
 */
class RabbitAlgo extends StreamCipher {
  constructor(...args) {
    super(...args);

    this.blockSize = 128 / 32;
    this.ivSize = 64 / 32;
  }

  _doReset() {
    // Shortcuts
    const K = this._key.words;
    const { iv } = this.cfg;

    // Swap endian
    for (let i = 0; i < 4; i += 1) {
      K[i] = (((K[i] << 8) | (K[i] >>> 24)) & 0x00ff00ff)
        | (((K[i] << 24) | (K[i] >>> 8)) & 0xff00ff00);
    }

    // Generate initial state values
    this._X = [
      K[0], (K[3] << 16) | (K[2] >>> 16),
      K[1], (K[0] << 16) | (K[3] >>> 16),
      K[2], (K[1] << 16) | (K[0] >>> 16),
      K[3], (K[2] << 16) | (K[1] >>> 16),
    ];
    const X = this._X;

    // Generate initial counter values
    this._C = [
      (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
      (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
      (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
      (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff),
    ];
    const C = this._C;

    // Carry bit
    this._b = 0;

    // Iterate the system four times
    for (let i = 0; i < 4; i += 1) {
      nextState$1.call(this);
    }

    // Modify the counters
    for (let i = 0; i < 8; i += 1) {
      C[i] ^= X[(i + 4) & 7];
    }

    // IV setup
    if (iv) {
      // Shortcuts
      const IV = iv.words;
      const IV_0 = IV[0];
      const IV_1 = IV[1];

      // Generate four subvectors
      const i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff)
        | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
      const i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff)
        | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
      const i1 = (i0 >>> 16) | (i2 & 0xffff0000);
      const i3 = (i2 << 16) | (i0 & 0x0000ffff);

      // Modify counter values
      C[0] ^= i0;
      C[1] ^= i1;
      C[2] ^= i2;
      C[3] ^= i3;
      C[4] ^= i0;
      C[5] ^= i1;
      C[6] ^= i2;
      C[7] ^= i3;

      // Iterate the system four times
      for (let i = 0; i < 4; i += 1) {
        nextState$1.call(this);
      }
    }
  }

  _doProcessBlock(M, offset) {
    const _M = M;

    // Shortcut
    const X = this._X;

    // Iterate the system
    nextState$1.call(this);

    // Generate four keystream words
    S$1[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
    S$1[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
    S$1[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
    S$1[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

    for (let i = 0; i < 4; i += 1) {
      // Swap endian
      S$1[i] = (((S$1[i] << 8) | (S$1[i] >>> 24)) & 0x00ff00ff)
        | (((S$1[i] << 24) | (S$1[i] >>> 8)) & 0xff00ff00);

      // Encrypt
      _M[offset + i] ^= S$1[i];
    }
  }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
 */
const Rabbit = StreamCipher._createHelper(RabbitAlgo);

// Reusable objects
const S = [];
const C_ = [];
const G = [];

function nextState() {
  // Shortcuts
  const X = this._X;
  const C = this._C;

  // Save old counter values
  for (let i = 0; i < 8; i += 1) {
    C_[i] = C[i];
  }

  // Calculate new counter values
  C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
  C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
  C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
  C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
  C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
  C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
  C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
  C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
  this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

  // Calculate the g-values
  for (let i = 0; i < 8; i += 1) {
    const gx = X[i] + C[i];

    // Construct high and low argument for squaring
    const ga = gx & 0xffff;
    const gb = gx >>> 16;

    // Calculate high and low result of squaring
    const gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
    const gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

    // High XOR low
    G[i] = gh ^ gl;
  }

  // Calculate new state values
  X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
  X[1] = (G[1] + ((G[0] << 8) | (G[0] >>> 24)) + G[7]) | 0;
  X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
  X[3] = (G[3] + ((G[2] << 8) | (G[2] >>> 24)) + G[1]) | 0;
  X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
  X[5] = (G[5] + ((G[4] << 8) | (G[4] >>> 24)) + G[3]) | 0;
  X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
  X[7] = (G[7] + ((G[6] << 8) | (G[6] >>> 24)) + G[5]) | 0;
}

/**
 * Rabbit stream cipher algorithm.
 *
 * This is a legacy version that neglected to convert the key to little-endian.
 * This error doesn't affect the cipher's security,
 * but it does affect its compatibility with other implementations.
 */
class RabbitLegacyAlgo extends StreamCipher {
  constructor(...args) {
    super(...args);

    this.blockSize = 128 / 32;
    this.ivSize = 64 / 32;
  }

  _doReset() {
    // Shortcuts
    const K = this._key.words;
    const { iv } = this.cfg;

    // Generate initial state values
    this._X = [
      K[0], (K[3] << 16) | (K[2] >>> 16),
      K[1], (K[0] << 16) | (K[3] >>> 16),
      K[2], (K[1] << 16) | (K[0] >>> 16),
      K[3], (K[2] << 16) | (K[1] >>> 16),
    ];
    const X = this._X;

    // Generate initial counter values
    this._C = [
      (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
      (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
      (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
      (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff),
    ];
    const C = this._C;

    // Carry bit
    this._b = 0;

    // Iterate the system four times
    for (let i = 0; i < 4; i += 1) {
      nextState.call(this);
    }

    // Modify the counters
    for (let i = 0; i < 8; i += 1) {
      C[i] ^= X[(i + 4) & 7];
    }

    // IV setup
    if (iv) {
      // Shortcuts
      const IV = iv.words;
      const IV_0 = IV[0];
      const IV_1 = IV[1];

      // Generate four subvectors
      const i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff)
        | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
      const i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff)
        | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
      const i1 = (i0 >>> 16) | (i2 & 0xffff0000);
      const i3 = (i2 << 16) | (i0 & 0x0000ffff);

      // Modify counter values
      C[0] ^= i0;
      C[1] ^= i1;
      C[2] ^= i2;
      C[3] ^= i3;
      C[4] ^= i0;
      C[5] ^= i1;
      C[6] ^= i2;
      C[7] ^= i3;

      // Iterate the system four times
      for (let i = 0; i < 4; i += 1) {
        nextState.call(this);
      }
    }
  }

  _doProcessBlock(M, offset) {
    const _M = M;

    // Shortcut
    const X = this._X;

    // Iterate the system
    nextState.call(this);

    // Generate four keystream words
    S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
    S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
    S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
    S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

    for (let i = 0; i < 4; i += 1) {
      // Swap endian
      S[i] = (((S[i] << 8) | (S[i] >>> 24)) & 0x00ff00ff)
        | (((S[i] << 24) | (S[i] >>> 8)) & 0xff00ff00);

      // Encrypt
      _M[offset + i] ^= S[i];
    }
  }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
 */
const RabbitLegacy = StreamCipher._createHelper(RabbitLegacyAlgo);

function generateKeystreamWord() {
  // Shortcuts
  const S = this._S;
  let i = this._i;
  let j = this._j;

  // Generate keystream word
  let keystreamWord = 0;
  for (let n = 0; n < 4; n += 1) {
    i = (i + 1) % 256;
    j = (j + S[i]) % 256;

    // Swap
    const t = S[i];
    S[i] = S[j];
    S[j] = t;

    keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
  }

  // Update counters
  this._i = i;
  this._j = j;

  return keystreamWord;
}

/**
 * RC4 stream cipher algorithm.
 */
class RC4Algo extends StreamCipher {
  _doReset() {
    // Shortcuts
    const key = this._key;
    const keyWords = key.words;
    const keySigBytes = key.sigBytes;

    // Init sbox
    this._S = [];
    const S = this._S;
    for (let i = 0; i < 256; i += 1) {
      S[i] = i;
    }

    // Key setup
    for (let i = 0, j = 0; i < 256; i += 1) {
      const keyByteIndex = i % keySigBytes;
      const keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

      j = (j + S[i] + keyByte) % 256;

      // Swap
      const t = S[i];
      S[i] = S[j];
      S[j] = t;
    }

    // Counters
    this._j = 0;
    this._i = this._j;
  }

  _doProcessBlock(M, offset) {
    const _M = M;

    _M[offset] ^= generateKeystreamWord.call(this);
  }
}
RC4Algo.keySize = 256 / 32;
RC4Algo.ivSize = 0;

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
 */
const RC4 = StreamCipher._createHelper(RC4Algo);

/**
 * Modified RC4 stream cipher algorithm.
 */
class RC4DropAlgo extends RC4Algo {
  constructor(...args) {
    super(...args);

    /**
     * Configuration options.
     *
     * @property {number} drop The number of keystream words to drop. Default 192
     */
    Object.assign(this.cfg, { drop: 192 });
  }

  _doReset() {
    super._doReset.call(this);

    // Drop
    for (let i = this.cfg.drop; i > 0; i -= 1) {
      generateKeystreamWord.call(this);
    }
  }
}

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
 */
const RC4Drop = StreamCipher._createHelper(RC4DropAlgo);

function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
  const _words = words;
  let keystream;

  // Shortcut
  const iv = this._iv;

  // Generate keystream
  if (iv) {
    keystream = iv.slice(0);

    // Remove IV for subsequent blocks
    this._iv = undefined;
  } else {
    keystream = this._prevBlock;
  }
  cipher.encryptBlock(keystream, 0);

  // Encrypt
  for (let i = 0; i < blockSize; i += 1) {
    _words[offset + i] ^= keystream[i];
  }
}

/**
 * Cipher Feedback block mode.
 */
class CFB extends BlockCipherMode {
}
CFB.Encryptor = class extends CFB {
  processBlock(words, offset) {
    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;

    generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

    // Remember this block to use with next block
    this._prevBlock = words.slice(offset, offset + blockSize);
  }
};
CFB.Decryptor = class extends CFB {
  processBlock(words, offset) {
    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;

    // Remember this block to use with next block
    const thisBlock = words.slice(offset, offset + blockSize);

    generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

    // This block becomes the previous block
    this._prevBlock = thisBlock;
  }
};

/**
 * Counter block mode.
 */

class CTR extends BlockCipherMode {
}
CTR.Encryptor = class extends CTR {
  processBlock(words, offset) {
    const _words = words;

    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;
    const iv = this._iv;
    let counter = this._counter;

    // Generate keystream
    if (iv) {
      this._counter = iv.slice(0);
      counter = this._counter;

      // Remove IV for subsequent blocks
      this._iv = undefined;
    }
    const keystream = counter.slice(0);
    cipher.encryptBlock(keystream, 0);

    // Increment counter
    counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0;

    // Encrypt
    for (let i = 0; i < blockSize; i += 1) {
      _words[offset + i] ^= keystream[i];
    }
  }
};
CTR.Decryptor = CTR.Encryptor;

const incWord = (word) => {
  let _word = word;

  if (((word >> 24) & 0xff) === 0xff) { // overflow
    let b1 = (word >> 16) & 0xff;
    let b2 = (word >> 8) & 0xff;
    let b3 = word & 0xff;

    if (b1 === 0xff) { // overflow b1
      b1 = 0;
      if (b2 === 0xff) {
        b2 = 0;
        if (b3 === 0xff) {
          b3 = 0;
        } else {
          b3 += 1;
        }
      } else {
        b2 += 1;
      }
    } else {
      b1 += 1;
    }

    _word = 0;
    _word += (b1 << 16);
    _word += (b2 << 8);
    _word += b3;
  } else {
    _word += (0x01 << 24);
  }
  return _word;
};

const incCounter = (counter) => {
  const _counter = counter;
  _counter[0] = incWord(_counter[0]);

  if (_counter[0] === 0) {
    // encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
    _counter[1] = incWord(_counter[1]);
  }
  return _counter;
};

/** @preserve
 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
 * derived from CryptoJS.mode.CTR
 * Jan Hruby jhruby.web@gmail.com
 */
class CTRGladman extends BlockCipherMode {
}
CTRGladman.Encryptor = class extends CTRGladman {
  processBlock(words, offset) {
    const _words = words;

    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;
    const iv = this._iv;
    let counter = this._counter;

    // Generate keystream
    if (iv) {
      this._counter = iv.slice(0);
      counter = this._counter;

      // Remove IV for subsequent blocks
      this._iv = undefined;
    }

    incCounter(counter);

    const keystream = counter.slice(0);
    cipher.encryptBlock(keystream, 0);

    // Encrypt
    for (let i = 0; i < blockSize; i += 1) {
      _words[offset + i] ^= keystream[i];
    }
  }
};
CTRGladman.Decryptor = CTRGladman.Encryptor;

/**
 * Electronic Codebook block mode.
 */

class ECB extends BlockCipherMode {
}
ECB.Encryptor = class extends ECB {
  processBlock(words, offset) {
    this._cipher.encryptBlock(words, offset);
  }
};
ECB.Decryptor = class extends ECB {
  processBlock(words, offset) {
    this._cipher.decryptBlock(words, offset);
  }
};

/**
 * Output Feedback block mode.
 */

class OFB extends BlockCipherMode {
}
OFB.Encryptor = class extends OFB {
  processBlock(words, offset) {
    const _words = words;

    // Shortcuts
    const cipher = this._cipher;
    const { blockSize } = cipher;
    const iv = this._iv;
    let keystream = this._keystream;

    // Generate keystream
    if (iv) {
      this._keystream = iv.slice(0);
      keystream = this._keystream;

      // Remove IV for subsequent blocks
      this._iv = undefined;
    }
    cipher.encryptBlock(keystream, 0);

    // Encrypt
    for (let i = 0; i < blockSize; i += 1) {
      _words[offset + i] ^= keystream[i];
    }
  }
};
OFB.Decryptor = OFB.Encryptor;

/**
 * ANSI X.923 padding strategy.
 */
const AnsiX923 = {
  pad(data, blockSize) {
    const _data = data;

    // Shortcuts
    const dataSigBytes = _data.sigBytes;
    const blockSizeBytes = blockSize * 4;

    // Count padding bytes
    const nPaddingBytes = blockSizeBytes - (dataSigBytes % blockSizeBytes);

    // Compute last byte position
    const lastBytePos = dataSigBytes + nPaddingBytes - 1;

    // Pad
    _data.clamp();
    _data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
    _data.sigBytes += nPaddingBytes;
  },

  unpad(data) {
    const _data = data;

    // Get number of padding bytes from last byte
    const nPaddingBytes = _data.words[(_data.sigBytes - 1) >>> 2] & 0xff;

    // Remove padding
    _data.sigBytes -= nPaddingBytes;
  },
};

/**
 * ISO 10126 padding strategy.
 */
const Iso10126 = {
  pad(data, blockSize) {
    // Shortcut
    const blockSizeBytes = blockSize * 4;

    // Count padding bytes
    const nPaddingBytes = blockSizeBytes - (data.sigBytes % blockSizeBytes);

    // Pad
    data
      .concat(WordArray.random(nPaddingBytes - 1))
      .concat(WordArray.create([nPaddingBytes << 24], 1));
  },

  unpad(data) {
    const _data = data;
    // Get number of padding bytes from last byte
    const nPaddingBytes = _data.words[(_data.sigBytes - 1) >>> 2] & 0xff;

    // Remove padding
    _data.sigBytes -= nPaddingBytes;
  },
};

/**
 * Zero padding strategy.
 */
const ZeroPadding = {
  pad(data, blockSize) {
    const _data = data;

    // Shortcut
    const blockSizeBytes = blockSize * 4;

    // Pad
    _data.clamp();
    _data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
  },

  unpad(data) {
    const _data = data;

    // Shortcut
    const dataWords = _data.words;

    // Unpad
    for (let i = _data.sigBytes - 1; i >= 0; i -= 1) {
      if (((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
        _data.sigBytes = i + 1;
        break;
      }
    }
  },
};

/**
 * ISO/IEC 9797-1 Padding Method 2.
 */
const Iso97971 = {
  pad(data, blockSize) {
    // Add 0x80 byte
    data.concat(WordArray.create([0x80000000], 1));

    // Zero pad the rest
    ZeroPadding.pad(data, blockSize);
  },

  unpad(data) {
    const _data = data;

    // Remove zero padding
    ZeroPadding.unpad(_data);

    // Remove one more byte -- the 0x80 byte
    _data.sigBytes -= 1;
  },
};

/**
 * A noop padding strategy.
 */
const NoPadding = {
  pad() {
  },

  unpad() {
  },
};

const HexFormatter = {
  /**
   * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
   *
   * @param {CipherParams} cipherParams The cipher params object.
   *
   * @return {string} The hexadecimally encoded string.
   *
   * @static
   *
   * @example
   *
   *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
   */
  stringify(cipherParams) {
    return cipherParams.ciphertext.toString(Hex);
  },

  /**
   * Converts a hexadecimally encoded ciphertext string to a cipher params object.
   *
   * @param {string} input The hexadecimally encoded string.
   *
   * @return {CipherParams} The cipher params object.
   *
   * @static
   *
   * @example
   *
   *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
   */
  parse(input) {
    const ciphertext = Hex.parse(input);
    return CipherParams.create({ ciphertext });
  },
};

var CryptoES = {
  lib: {
    Base,
    WordArray,
    BufferedBlockAlgorithm,
    Hasher,
    Cipher,
    StreamCipher,
    BlockCipherMode,
    BlockCipher,
    CipherParams,
    SerializableCipher,
    PasswordBasedCipher,
  },

  x64: {
    Word: X64Word,
    WordArray: X64WordArray,
  },

  enc: {
    Hex,
    Latin1,
    Utf8,
    Utf16,
    Utf16BE,
    Utf16LE,
    Base64,
  },

  algo: {
    HMAC,
    MD5: MD5Algo,
    SHA1: SHA1Algo,
    SHA224: SHA224Algo,
    SHA256: SHA256Algo,
    SHA384: SHA384Algo,
    SHA512: SHA512Algo,
    SHA3: SHA3Algo,
    RIPEMD160: RIPEMD160Algo,

    PBKDF2: PBKDF2Algo,
    EvpKDF: EvpKDFAlgo,

    AES: AESAlgo,
    DES: DESAlgo,
    TripleDES: TripleDESAlgo,
    Rabbit: RabbitAlgo,
    RabbitLegacy: RabbitLegacyAlgo,
    RC4: RC4Algo,
    RC4Drop: RC4DropAlgo,
  },

  mode: {
    CBC,
    CFB,
    CTR,
    CTRGladman,
    ECB,
    OFB,
  },

  pad: {
    Pkcs7,
    AnsiX923,
    Iso10126,
    Iso97971,
    NoPadding,
    ZeroPadding,
  },

  format: {
    OpenSSL: OpenSSLFormatter,
    Hex: HexFormatter,
  },

  kdf: {
    OpenSSL: OpenSSLKdf,
  },

  MD5,
  HmacMD5,
  SHA1,
  HmacSHA1,
  SHA224,
  HmacSHA224,
  SHA256,
  HmacSHA256,
  SHA384,
  HmacSHA384,
  SHA512,
  HmacSHA512,
  SHA3,
  HmacSHA3,
  RIPEMD160,
  HmacRIPEMD160,

  PBKDF2,
  EvpKDF,

  AES,
  DES,
  TripleDES,
  Rabbit,
  RabbitLegacy,
  RC4,
  RC4Drop,
};

class SecureModeCrypt {
    static encryptString(string, key) {
        return CryptoES.AES.encrypt(string, key).toString();
    }
    static decryptString(string, key) {
        return CryptoES.AES.decrypt(string, key).toString(CryptoES.enc.Utf8);
    }
}

/* src\Modals\SecureModeGetPasswordModal\SecureModeGetPasswordModalContent.svelte generated by Svelte v3.37.0 */

function create_fragment$1(ctx) {
	let div;
	let h2;
	let t1;
	let p;
	let t3;
	let label;
	let input;
	let t4;
	let button;
	let mounted;
	let dispose;

	return {
		c() {
			div = element("div");
			h2 = element("h2");
			h2.textContent = "Secure Mode";
			t1 = space();
			p = element("p");
			p.textContent = "Please enter your password to continue.";
			t3 = space();
			label = element("label");
			input = element("input");
			t4 = space();
			button = element("button");
			button.textContent = "Submit";
			attr(input, "type", "password");
			set_style(button, "margin-left", "1rem");
		},
		m(target, anchor) {
			insert(target, div, anchor);
			append(div, h2);
			append(div, t1);
			append(div, p);
			append(div, t3);
			append(div, label);
			append(label, input);
			/*input_binding*/ ctx[2](input);
			append(div, t4);
			append(div, button);

			if (!mounted) {
				dispose = listen(button, "click", /*click_handler*/ ctx[3]);
				mounted = true;
			}
		},
		p: noop,
		i: noop,
		o: noop,
		d(detaching) {
			if (detaching) detach(div);
			/*input_binding*/ ctx[2](null);
			mounted = false;
			dispose();
		}
	};
}

function instance$1($$self, $$props, $$invalidate) {
	let passwordInput;
	let { onSubmit } = $$props;

	function input_binding($$value) {
		binding_callbacks[$$value ? "unshift" : "push"](() => {
			passwordInput = $$value;
			$$invalidate(1, passwordInput);
		});
	}

	const click_handler = () => onSubmit(passwordInput.value);

	$$self.$$set = $$props => {
		if ("onSubmit" in $$props) $$invalidate(0, onSubmit = $$props.onSubmit);
	};

	return [onSubmit, passwordInput, input_binding, click_handler];
}

class SecureModeGetPasswordModalContent extends SvelteComponent {
	constructor(options) {
		super();
		init(this, options, instance$1, create_fragment$1, safe_not_equal, { onSubmit: 0 });
	}
}

class SecureModeGetPasswordModal extends obsidian.Modal {
    constructor(app, plugin) {
        super(app);
        this._plugin = plugin;
        this.waitForClose = new Promise((resolve) => (this.resolvePromise = resolve));
        this.modalContent = new SecureModeGetPasswordModalContent({
            target: this.contentEl,
            props: {
                onSubmit: (value) => this.onSubmit(value),
            },
        });
        this.open();
    }
    onClose() {
        super.onClose();
        this.modalContent.$destroy();
        this.resolvePromise();
    }
    onSubmit(value) {
        if (value === "")
            return;
        try {
            this.secureModeLogin(value);
        }
        catch (e) {
            new obsidian.Notice("Wrong password.");
        }
        if (this._plugin.twitterHandler.isConnectedToTwitter) {
            new obsidian.Notice("Successfully authenticated with Twitter!");
            this.close();
        }
    }
    secureModeLogin(password) {
        this._plugin.twitterHandler.connectToTwitter(SecureModeCrypt.decryptString(this._plugin.settings.apiKey, password), SecureModeCrypt.decryptString(this._plugin.settings.apiSecret, password), SecureModeCrypt.decryptString(this._plugin.settings.accessToken, password), SecureModeCrypt.decryptString(this._plugin.settings.accessTokenSecret, password));
    }
}

class PostTweetModal extends obsidian.Modal {
    constructor(app, twitterHandler, selection) {
        super(app);
        this.textAreas = [];
        this.MAX_TWEET_LENGTH = 280;
        this.helpText = `Please read the documentation on the Github repository.
                        Click <a target="_blank" href="https://github.com/chhoumann/notetweet_obsidian">here</a> to go there.
                        There are lots of shortcuts and features to explore 😁`;
        this.selectedText = selection !== null && selection !== void 0 ? selection : { text: "", thread: false };
        this.twitterHandler = twitterHandler;
    }
    onOpen() {
        let { contentEl } = this;
        contentEl.addClass("postTweetModal");
        this.addTooltip("Help", this.helpText, contentEl);
        let textZone = contentEl.createDiv();
        try {
            let textArea = this.createTextarea(textZone);
            this.selectedTextHandler(textArea, textZone);
            let addTweetButton = contentEl.createEl("button", { text: "+" });
            addTweetButton.addEventListener("click", () => this.createTextarea(textZone));
            this.createTweetButton(contentEl);
        }
        catch (e) {
            new obsidian.Notice(e);
            this.close();
            return;
        }
    }
    selectedTextHandler(textArea, textZone) {
        if (this.selectedText.text.length == 0)
            return false;
        let joinedTextChunks;
        if (this.selectedText.thread == false)
            joinedTextChunks = this.textInputHandler(this.selectedText.text);
        else
            joinedTextChunks = this.selectedText.text.split("--nt_sep--");
        this.createTweetsWithInput(joinedTextChunks, textArea, textZone);
    }
    createTweetsWithInput(inputStrings, currentTextArea, textZone) {
        inputStrings.forEach((chunk) => {
            try {
                let tempTextarea = currentTextArea.value.trim() == ""
                    ? currentTextArea
                    : this.createTextarea(textZone);
                tempTextarea.setRangeText(chunk);
                tempTextarea.dispatchEvent(new InputEvent("input"));
                tempTextarea.style.height = tempTextarea.scrollHeight + "px";
            }
            catch (e) {
                new obsidian.Notice(e);
                return;
            }
        });
    }
    // Separate lines by linebreaks. Add lines together, separated by linebreak, if they can fit within a tweet.
    // Repeat this until all separated lines are joined into tweets with proper sizes.
    textInputHandler(str) {
        let chunks = str.split("\n");
        let i = 0, joinedTextChunks = [];
        chunks.forEach((chunk, j) => {
            if (joinedTextChunks[i] == null)
                joinedTextChunks[i] = "";
            if (joinedTextChunks[i].length + chunk.length <=
                this.MAX_TWEET_LENGTH - 1) {
                joinedTextChunks[i] = joinedTextChunks[i] + chunk;
                joinedTextChunks[i] += j == chunks.length - 1 ? "" : "\n";
            }
            else {
                if (chunk.length > this.MAX_TWEET_LENGTH) {
                    let x = chunk.split(/[.?!]\s/).join("\n");
                    this.textInputHandler(x).forEach((split) => (joinedTextChunks[++i] = split));
                }
                else {
                    joinedTextChunks[++i] = chunk;
                }
            }
        });
        return joinedTextChunks;
    }
    onClose() {
        let { contentEl } = this;
        contentEl.empty();
    }
    createTextarea(textZone) {
        if (this.textAreas.find((ele) => ele.textLength == 0)) {
            throw new Error("You cannot add a new tweet when there are empty tweets.");
        }
        let textarea = textZone.createEl("textarea");
        this.textAreas.push(textarea);
        textarea.addClass("tweetArea");
        let lengthCheckerEl = textZone.createEl("p", {
            text: "0 / 280 characters.",
        });
        lengthCheckerEl.addClass("ntLengthChecker");
        textarea.addEventListener("input", () => this.onTweetLengthHandler(textarea.textLength, lengthCheckerEl));
        textarea.addEventListener("keydown", this.onInput(textarea, textZone, lengthCheckerEl));
        textarea.addEventListener("paste", this.onPasteMaxLengthHandler(textarea, textZone));
        textarea.focus();
        return textarea;
    }
    addTooltip(title, body, root) {
        let tooltip = root.createEl("div", { text: title });
        let tooltipBody = tooltip.createEl("span");
        tooltipBody.innerHTML = body;
        tooltip.addClass("tweetTooltip");
        tooltipBody.addClass("tweetTooltipBody");
    }
    onPasteMaxLengthHandler(textarea, textZone) {
        return (event) => {
            let pasted = event.clipboardData.getData("text");
            if (pasted.length + textarea.textLength > this.MAX_TWEET_LENGTH) {
                event.preventDefault();
                let splicedPaste = this.textInputHandler(pasted);
                this.createTweetsWithInput(splicedPaste, textarea, textZone);
            }
        };
    }
    onInput(textarea, textZone, lengthCheckerEl) {
        return (key) => {
            if (key.code == "Backspace" &&
                textarea.textLength == 0 &&
                this.textAreas.length > 1) {
                key.preventDefault();
                this.deleteTweet(textarea, textZone, lengthCheckerEl);
            }
            if (key.code == "Enter" && textarea.textLength >= this.MAX_TWEET_LENGTH) {
                key.preventDefault();
                try {
                    this.createTextarea(textZone);
                }
                catch (e) {
                    new obsidian.Notice(e);
                    return;
                }
            }
            if ((key.code == "Enter" || key.code == "NumpadEnter") && key.altKey) {
                key.preventDefault();
                try {
                    this.createTextarea(textZone);
                }
                catch (e) {
                    new obsidian.Notice(e);
                    return;
                }
            }
            if (key.code == "Enter" && key.shiftKey) {
                key.preventDefault();
                this.insertTweetAbove(textarea, textZone);
            }
            if (key.code == "Enter" && key.ctrlKey) {
                key.preventDefault();
                this.insertTweetBelow(textarea, textZone);
            }
            if (key.code == "ArrowUp" && key.ctrlKey && !key.shiftKey) {
                let currentTweetIndex = this.textAreas.findIndex((tweet) => tweet.value == textarea.value);
                if (currentTweetIndex > 0)
                    this.textAreas[currentTweetIndex - 1].focus();
            }
            if (key.code == "ArrowDown" && key.ctrlKey && !key.shiftKey) {
                let currentTweetIndex = this.textAreas.findIndex((tweet) => tweet.value == textarea.value);
                if (currentTweetIndex < this.textAreas.length - 1)
                    this.textAreas[currentTweetIndex + 1].focus();
            }
            if (key.code == "ArrowDown" && key.ctrlKey && key.shiftKey) {
                let tweetIndex = this.textAreas.findIndex((ta) => ta.value == textarea.value);
                if (tweetIndex != this.textAreas.length - 1) {
                    key.preventDefault();
                    this.switchTweets(textarea, this.textAreas[tweetIndex + 1]);
                    this.textAreas[tweetIndex + 1].focus();
                }
            }
            if (key.code == "ArrowUp" && key.ctrlKey && key.shiftKey) {
                let tweetIndex = this.textAreas.findIndex((ta) => ta.value == textarea.value);
                if (tweetIndex != 0) {
                    key.preventDefault();
                    this.switchTweets(textarea, this.textAreas[tweetIndex - 1]);
                    this.textAreas[tweetIndex - 1].focus();
                }
            }
            if (key.code == "Delete" && key.ctrlKey && key.shiftKey) {
                key.preventDefault();
                if (this.textAreas.length == 1)
                    textarea.value = "";
                else
                    this.deleteTweet(textarea, textZone, lengthCheckerEl);
            }
            textarea.style.height = "auto";
            textarea.style.height = textarea.scrollHeight + "px";
        };
    }
    switchTweets(textarea1, textarea2) {
        let temp = textarea1.value;
        textarea1.value = textarea2.value;
        textarea2.value = temp;
        textarea1.dispatchEvent(new InputEvent("input"));
        textarea2.dispatchEvent(new InputEvent("input"));
    }
    deleteTweet(textarea, textZone, lengthCheckerEl) {
        let i = this.textAreas.findIndex((ele) => ele === textarea);
        this.textAreas.remove(textarea);
        textZone.removeChild(textarea);
        textZone.removeChild(lengthCheckerEl);
        this.textAreas[i == 0 ? i : i - 1].focus();
    }
    onTweetLengthHandler(strlen, lengthCheckerEl) {
        const WARN1 = this.MAX_TWEET_LENGTH - 50;
        const WARN2 = this.MAX_TWEET_LENGTH - 25;
        const DEFAULT_COLOR = "#339900";
        lengthCheckerEl.innerText = `${strlen} / 280 characters.`;
        if (strlen <= WARN1)
            lengthCheckerEl.style.color = DEFAULT_COLOR;
        if (strlen > WARN1)
            lengthCheckerEl.style.color = "#ffcc00";
        if (strlen > WARN2)
            lengthCheckerEl.style.color = "#ff9966";
        if (strlen >= this.MAX_TWEET_LENGTH) {
            lengthCheckerEl.style.color = "#cc3300";
        }
    }
    createTweetButton(contentEl) {
        let postButton = contentEl.createEl("button", { text: "Post!" });
        postButton.addClass("postTweetButton");
        postButton.addEventListener("click", this.postTweets());
    }
    postTweets() {
        return async () => {
            let threadContent = this.textAreas.map((textarea) => textarea.value);
            if (threadContent.find((txt) => txt.length > this.MAX_TWEET_LENGTH || txt == "") != null) {
                new obsidian.Notice("At least one of your tweets is too long or empty.");
                return;
            }
            try {
                let postedTweets = await this.twitterHandler.postThread(threadContent);
                let postedModal = new TweetsPostedModal(this.app, postedTweets, this.twitterHandler);
                postedModal.open();
            }
            catch (e) {
                new TweetErrorModal(this.app, e.data || e).open();
            }
            this.close();
        };
    }
    insertTweetAbove(textarea, textZone) {
        let insertAboveIndex = this.textAreas.findIndex((area) => area.value == textarea.value);
        try {
            let insertedTweet = this.createTextarea(textZone);
            this.shiftTweetsDownFromIndex(insertAboveIndex);
            return { tweet: insertedTweet, index: insertAboveIndex };
        }
        catch (e) {
            new obsidian.Notice(e);
            return;
        }
    }
    insertTweetBelow(textarea, textZone) {
        let insertBelowIndex = this.textAreas.findIndex((area) => area.value == textarea.value);
        let fromIndex = insertBelowIndex + 1;
        try {
            let insertedTextarea = this.createTextarea(textZone);
            this.shiftTweetsDownFromIndex(fromIndex);
            return insertedTextarea;
        }
        catch (e) {
            new obsidian.Notice(e);
        }
    }
    shiftTweetsDownFromIndex(insertedIndex) {
        for (let i = this.textAreas.length - 1; i > insertedIndex; i--) {
            this.textAreas[i].value = this.textAreas[i - 1].value;
            this.textAreas[i].dispatchEvent(new InputEvent("input"));
        }
        this.textAreas[insertedIndex].value = "";
        this.textAreas[insertedIndex].focus();
    }
}

/* src\Modals\SecureModeSettingModal\SecureModeSettingModalContent.svelte generated by Svelte v3.37.0 */

function create_fragment(ctx) {
	let div1;
	let h1;
	let t1;
	let p;
	let t3;
	let div0;
	let t9;
	let label;
	let input;
	let t10;
	let button;
	let t11_value = (/*enable*/ ctx[0] ? "Encrypt!" : "Decrypt!") + "";
	let t11;
	let mounted;
	let dispose;

	return {
		c() {
			div1 = element("div");
			h1 = element("h1");
			h1.textContent = "Secure Mode Settings";
			t1 = space();
			p = element("p");
			p.textContent = "Please enter your password below and then click the button below.";
			t3 = space();
			div0 = element("div");

			div0.innerHTML = `Help
        <span class="tweetTooltipBody">Secure Mode enables you to encrypt your API keys with a password.
            The password will be required to use the plugin while Secure Mode is enabled.<br/>
            Your API keys will remain stored, but will be overwritten with the encrypted keys.
            This means they will be unintelligible to anyone who doesn&#39;t know your password.<br/> 
            <strong>Please do note that this plugin cannot check if your passwords decrypts your keys correctly!
            This means you might have to re-enter your keys if the wrong password is entered.</strong></span>`;

			t9 = space();
			label = element("label");
			input = element("input");
			t10 = space();
			button = element("button");
			t11 = text(t11_value);
			attr(div0, "class", "tweetTooltip");
			set_style(div0, "float", "right");
			attr(input, "type", "password");
			set_style(button, "margin-left", "1rem");
		},
		m(target, anchor) {
			insert(target, div1, anchor);
			append(div1, h1);
			append(div1, t1);
			append(div1, p);
			append(div1, t3);
			append(div1, div0);
			append(div1, t9);
			append(div1, label);
			append(label, input);
			set_input_value(input, /*passwordInput*/ ctx[2]);
			append(div1, t10);
			append(div1, button);
			append(button, t11);

			if (!mounted) {
				dispose = [
					listen(input, "input", /*input_input_handler*/ ctx[3]),
					listen(button, "click", /*click_handler*/ ctx[4])
				];

				mounted = true;
			}
		},
		p(ctx, [dirty]) {
			if (dirty & /*passwordInput*/ 4 && input.value !== /*passwordInput*/ ctx[2]) {
				set_input_value(input, /*passwordInput*/ ctx[2]);
			}

			if (dirty & /*enable*/ 1 && t11_value !== (t11_value = (/*enable*/ ctx[0] ? "Encrypt!" : "Decrypt!") + "")) set_data(t11, t11_value);
		},
		i: noop,
		o: noop,
		d(detaching) {
			if (detaching) detach(div1);
			mounted = false;
			run_all(dispose);
		}
	};
}

function instance($$self, $$props, $$invalidate) {
	let { enable } = $$props;
	let { onSubmit } = $$props;
	let passwordInput;

	function input_input_handler() {
		passwordInput = this.value;
		$$invalidate(2, passwordInput);
	}

	const click_handler = () => onSubmit(passwordInput);

	$$self.$$set = $$props => {
		if ("enable" in $$props) $$invalidate(0, enable = $$props.enable);
		if ("onSubmit" in $$props) $$invalidate(1, onSubmit = $$props.onSubmit);
	};

	return [enable, onSubmit, passwordInput, input_input_handler, click_handler];
}

class SecureModeSettingModalContent extends SvelteComponent {
	constructor(options) {
		super();
		init(this, options, instance, create_fragment, safe_not_equal, { enable: 0, onSubmit: 1 });
	}
}

class SecureModeModal extends obsidian.Modal {
    constructor(app, plugin, enable) {
        super(app);
        this.userPressedCrypt = false;
        this.plugin = plugin;
        this.enable = enable;
        this.waitForResolve = new Promise((resolve) => (this.resolvePromise = resolve));
        this.secureModeSettingModalContent = new SecureModeSettingModalContent({
            target: this.contentEl,
            props: {
                enable: this.enable,
                userPressedCrypt: this.userPressedCrypt,
                onSubmit: (value) => this.onSubmit(value),
            },
        });
        this.open();
    }
    async onSubmit(value) {
        this.enable
            ? await this.encryptKeysWithPassword(value)
            : await this.decryptKeysWithPassword(value);
        this.userPressedCrypt = true;
        this.close();
    }
    onClose() {
        super.onClose();
        this.secureModeSettingModalContent.$destroy();
        this.resolvePromise();
    }
    async encryptKeysWithPassword(password) {
        this.plugin.settings.apiKey = SecureModeCrypt.encryptString(this.plugin.settings.apiKey, password);
        this.plugin.settings.apiSecret = SecureModeCrypt.encryptString(this.plugin.settings.apiSecret, password);
        this.plugin.settings.accessToken = SecureModeCrypt.encryptString(this.plugin.settings.accessToken, password);
        this.plugin.settings.accessTokenSecret = SecureModeCrypt.encryptString(this.plugin.settings.accessTokenSecret, password);
        await this.plugin.saveSettings();
    }
    async decryptKeysWithPassword(password) {
        this.plugin.settings.apiKey = SecureModeCrypt.decryptString(this.plugin.settings.apiKey, password);
        this.plugin.settings.apiSecret = SecureModeCrypt.decryptString(this.plugin.settings.apiSecret, password);
        this.plugin.settings.accessToken = SecureModeCrypt.decryptString(this.plugin.settings.accessToken, password);
        this.plugin.settings.accessTokenSecret = SecureModeCrypt.decryptString(this.plugin.settings.accessTokenSecret, password);
        await this.plugin.saveSettings();
    }
}

const DEFAULT_SETTINGS = Object.freeze({
    apiKey: "",
    apiSecret: "",
    accessToken: "",
    accessTokenSecret: "",
    postTweetTag: "",
    secureMode: false,
});
class NoteTweetSettingsTab extends obsidian.PluginSettingTab {
    constructor(app, plugin) {
        super(app, plugin);
        this.plugin = plugin;
    }
    checkStatus() {
        this.statusIndicator.innerHTML = `<strong>Plugin Status:</strong> ${this.plugin.twitterHandler.isConnectedToTwitter
            ? "✅ Plugin connected to Twitter."
            : "🛑 Plugin not connected to Twitter."}`;
    }
    display() {
        let { containerEl } = this;
        containerEl.empty();
        containerEl.createEl("h2", { text: "NoteTweet" });
        this.statusIndicator = containerEl.createEl("p");
        this.checkStatus();
        this.addApiKeySetting();
        this.addApiSecretSetting();
        this.addAccessTokenSetting();
        this.addAccessTokenSecretSetting();
        this.addTweetTagSetting();
        this.addSecureModeSetting();
    }
    addSecureModeSetting() {
        new obsidian.Setting(this.containerEl)
            .setName("Secure Mode")
            .setDesc("Require password to unlock usage.")
            .addToggle((toggle) => toggle
            .setTooltip("Toggle Secure Mode")
            .setValue(this.plugin.settings.secureMode)
            .onChange(async (value) => {
            if (value == this.plugin.settings.secureMode)
                return;
            let secureModeModal = new SecureModeModal(this.app, this.plugin, value);
            await secureModeModal.waitForResolve;
            if (secureModeModal.userPressedCrypt) {
                this.plugin.settings.secureMode = value;
                await this.plugin.saveSettings();
                this.display();
            }
            toggle.setValue(this.plugin.settings.secureMode);
            this.display();
        }));
    }
    addTweetTagSetting() {
        new obsidian.Setting(this.containerEl)
            .setName("Tweet Tag")
            .setDesc("Appended to your tweets to indicate that it has been posted.")
            .addText((text) => text
            .setPlaceholder("Tag to append")
            .setValue(this.plugin.settings.postTweetTag)
            .onChange(async (value) => {
            this.plugin.settings.postTweetTag = value;
            await this.plugin.saveSettings();
        }));
    }
    addAccessTokenSecretSetting() {
        new obsidian.Setting(this.containerEl)
            .setName("Access Token Secret")
            .setDesc("Twitter Access Token Secret.")
            .addText((text) => text
            .setPlaceholder("Enter your Access Token Secret")
            .setValue(this.plugin.settings.accessTokenSecret)
            .onChange(async (value) => {
            this.plugin.settings.accessTokenSecret = value;
            await this.plugin.saveSettings();
            this.plugin.connectToTwitterWithPlainSettings();
            this.checkStatus();
        }));
    }
    addAccessTokenSetting() {
        new obsidian.Setting(this.containerEl)
            .setName("Access Token")
            .setDesc("Twitter Access Token.")
            .addText((text) => text
            .setPlaceholder("Enter your Access Token")
            .setValue(this.plugin.settings.accessToken)
            .onChange(async (value) => {
            this.plugin.settings.accessToken = value;
            await this.plugin.saveSettings();
            this.plugin.connectToTwitterWithPlainSettings();
            this.checkStatus();
        }));
    }
    addApiSecretSetting() {
        new obsidian.Setting(this.containerEl)
            .setName("API Secret")
            .setDesc("Twitter API Secret.")
            .addText((text) => text
            .setPlaceholder("Enter your API Secret")
            .setValue(this.plugin.settings.apiSecret)
            .onChange(async (value) => {
            this.plugin.settings.apiSecret = value;
            await this.plugin.saveSettings();
            this.plugin.connectToTwitterWithPlainSettings();
            this.checkStatus();
        }));
    }
    addApiKeySetting() {
        new obsidian.Setting(this.containerEl)
            .setName("API Key")
            .setDesc("Twitter API key.")
            .addText((text) => text
            .setPlaceholder("Enter your API key")
            .setValue(this.plugin.settings.apiKey)
            .onChange(async (value) => {
            this.plugin.settings.apiKey = value;
            await this.plugin.saveSettings();
            this.plugin.connectToTwitterWithPlainSettings();
            this.checkStatus();
        }));
    }
}

const WELCOME_MESSAGE = "Loading NoteTweet🐦. Thanks for installing.";
const UNLOAD_MESSAGE = "Unloaded NoteTweet.";
class NoteTweet extends obsidian.Plugin {
    async onload() {
        console.log(WELCOME_MESSAGE);
        await this.loadSettings();
        this.twitterHandler = new TwitterHandler();
        this.connectToTwitterWithPlainSettings();
        this.addCommand({
            id: "post-selected-as-tweet",
            name: "Post Selected as Tweet",
            callback: async () => {
                if (this.twitterHandler.isConnectedToTwitter)
                    await this.postSelectedTweet();
                else if (this.settings.secureMode)
                    await this.secureModeProxy(async () => await this.postSelectedTweet());
                else {
                    this.connectToTwitterWithPlainSettings();
                    if (!this.twitterHandler.isConnectedToTwitter)
                        new TweetErrorModal(this.app, "Not connected to Twitter").open();
                    else
                        await this.postSelectedTweet();
                }
            },
        });
        this.addCommand({
            id: "post-file-as-thread",
            name: "Post File as Thread",
            callback: async () => {
                if (this.twitterHandler.isConnectedToTwitter)
                    await this.postThreadInFile();
                else if (this.settings.secureMode)
                    await this.secureModeProxy(async () => await this.postThreadInFile());
                else {
                    this.connectToTwitterWithPlainSettings();
                    if (!this.twitterHandler.isConnectedToTwitter)
                        new TweetErrorModal(this.app, "Not connected to Twitter").open();
                    else
                        await this.postThreadInFile();
                }
            },
        });
        this.addCommand({
            id: "post-tweet",
            name: "Post Tweet",
            callback: async () => {
                if (this.twitterHandler.isConnectedToTwitter)
                    this.postTweetMode();
                else if (this.settings.secureMode)
                    await this.secureModeProxy(() => this.postTweetMode());
                else {
                    this.connectToTwitterWithPlainSettings();
                    if (!this.twitterHandler.isConnectedToTwitter)
                        new TweetErrorModal(this.app, "Not connected to Twitter").open();
                    else
                        this.postTweetMode();
                }
            },
        });
        /*START.DEVCMD*/
        this.addCommand({
            id: 'reloadNoteTweet',
            name: 'Reload NoteTweet (dev)',
            callback: () => {
                const id = this.manifest.id, plugins = this.app.plugins;
                plugins.disablePlugin(id).then(() => plugins.enablePlugin(id));
            },
        });
        /*END.DEVCMD*/
        this.addSettingTab(new NoteTweetSettingsTab(this.app, this));
    }
    postTweetMode() {
        const view = this.app.workspace.getActiveViewOfType(obsidian.MarkdownView);
        let editor;
        if (view instanceof obsidian.MarkdownView) {
            editor = view.editor;
        }
        else {
            return;
        }
        if (editor.somethingSelected()) {
            let selection = editor.getSelection();
            try {
                selection = this.parseThreadFromText(selection).join("--nt_sep--");
                new PostTweetModal(this.app, this.twitterHandler, {
                    text: selection,
                    thread: true,
                }).open();
            }
            catch (_a) {
                new PostTweetModal(this.app, this.twitterHandler, {
                    text: selection,
                    thread: false,
                }).open();
            } // Intentionally suppressing exceptions. They're expected.
        }
        else {
            new PostTweetModal(this.app, this.twitterHandler).open();
        }
    }
    connectToTwitterWithPlainSettings() {
        if (!this.settings.secureMode) {
            let { apiKey, apiSecret, accessToken, accessTokenSecret } = this.settings;
            if (!apiKey || !apiSecret || !accessToken || !accessTokenSecret)
                return;
            this.twitterHandler.connectToTwitter(apiKey, apiSecret, accessToken, accessTokenSecret);
        }
    }
    async postThreadInFile() {
        const file = this.app.workspace.getActiveFile();
        let content = await this.getFileContent(file);
        let threadContent;
        try {
            threadContent = this.parseThreadFromText(content);
        }
        catch (e) {
            new TweetErrorModal(this.app, e).open();
            return;
        }
        try {
            let postedTweets = await this.twitterHandler.postThread(threadContent);
            let postedModal = new TweetsPostedModal(this.app, postedTweets, this.twitterHandler);
            await postedModal.waitForClose;
            if (!postedModal.userDeletedTweets && this.settings.postTweetTag) {
                postedTweets.forEach((tweet) => this.appendPostTweetTag(tweet.text));
            }
        }
        catch (e) {
            new TweetErrorModal(this.app, e.data || e).open();
        }
    }
    async postSelectedTweet() {
        const view = this.app.workspace.getActiveViewOfType(obsidian.MarkdownView);
        let editor;
        if (view instanceof obsidian.MarkdownView) {
            editor = view.editor;
        }
        else {
            return;
        }
        if (editor.somethingSelected()) {
            let selection = editor.getSelection();
            try {
                let tweet = await this.twitterHandler.postTweet(selection);
                let postedModal = new TweetsPostedModal(this.app, [tweet], this.twitterHandler);
                await postedModal.waitForClose;
                if (!postedModal.userDeletedTweets && this.settings.postTweetTag) {
                    await this.appendPostTweetTag(tweet.text);
                }
            }
            catch (e) {
                new TweetErrorModal(this.app, e.data || e).open();
            }
        }
        else {
            new TweetErrorModal(this.app, "nothing selected.").open();
        }
    }
    async secureModeProxy(callback) {
        if (!(this.settings.secureMode && !this.twitterHandler.isConnectedToTwitter))
            return;
        let modal = new SecureModeGetPasswordModal(this.app, this);
        modal.waitForClose
            .then(async () => {
            if (this.twitterHandler.isConnectedToTwitter)
                await callback();
            else
                new obsidian.Notice("Could not connect to Twitter");
        })
            .catch(() => {
            modal.close();
            new obsidian.Notice("Could not connect to Twitter.");
        });
    }
    onunload() {
        console.log(UNLOAD_MESSAGE);
    }
    async loadSettings() {
        this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
    }
    async saveSettings() {
        await this.saveData(this.settings);
    }
    async getFileContent(file) {
        if (file.extension != "md")
            return null;
        return await this.app.vault.read(file);
    }
    // All threads start with THREAD START and ends with THREAD END. To separate tweets in a thread,
    // one should use use a newline and '---' (this prevents markdown from believing the above tweet is a heading).
    // We also purposefully remove the newline after the separator - otherwise tweets will be posted with a newline
    // as their first line.
    parseThreadFromText(text) {
        let contentArray = text.split("\n");
        let threadStartIndex = contentArray.indexOf("THREAD START") + 1;
        let threadEndIndex = contentArray.indexOf("THREAD END");
        if (threadStartIndex == 0 || threadEndIndex == -1) {
            throw new Error("Failed to detect THREAD START or THREAD END");
        }
        let content = contentArray
            .slice(threadStartIndex, threadEndIndex)
            .join("\n")
            .split("\n---\n");
        if (content.length == 1 && content[0] == "") {
            throw new Error("Please write something in your thread.");
        }
        return content.map((txt) => txt.trim());
    }
    async appendPostTweetTag(selection) {
        const currentFile = this.app.workspace.getActiveFile();
        let pageContent = await this.getFileContent(currentFile);
        pageContent = pageContent.replace(selection.trim(), `${selection.trim()} ${this.settings.postTweetTag}`);
        await this.app.vault.modify(currentFile, pageContent);
    }
}

module.exports = NoteTweet;
