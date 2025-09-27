Java.perform(function(){
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }
  try {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Buffer = Java.use('okio.Buffer');
    var Base64 = Java.use('android.util.Base64');
    var newCall_over = OkHttpClient.newCall.overload('okhttp3.Request');

    newCall_over.implementation = function(request){
      try {
        var url = "(unknown)"; try { url = request.url().toString(); } catch(e){}
        log('[okhttp hook] url=', url);
        try {
          var body = request.body();
          if (body) {
            var buf = Buffer.$new();
            body.writeTo(buf);
            var bytes = buf.readByteArray();
            log('[okhttp hook][body][base64]', Base64.encodeToString(bytes, 0));
          } else {
            log('[okhttp hook] no body');
          }
        } catch(e){ log('[okhttp hook] read body err:', e); }
        return newCall_over.call(this, request);
      } catch(inner){
        try { return newCall_over.call(this, request); } catch(e){ return this.newCall(request); }
      }
    };
    log('[okhttp hook] installed');
  } catch(e){
    log('[okhttp hook] install failed:', e);
  }
});
