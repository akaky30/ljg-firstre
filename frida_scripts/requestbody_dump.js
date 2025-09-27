Java.perform(function() {
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }
  try {
    var RequestBody = Java.use("okhttp3.RequestBody");
    var Buffer = Java.use("okio.Buffer");
    var Base64 = Java.use("android.util.Base64");
    var writeToOver = RequestBody.writeTo.overload("okio.BufferedSink");

    writeToOver.implementation = function(sink) {
      try {
        var buf = Buffer.$new();
        writeToOver.call(this, buf);           // 先写到内存
        var bytes = buf.readByteArray();
        log("[RequestBody] base64:", Base64.encodeToString(bytes, 0));
      } catch(e) { log("RB err:", e); }
      return writeToOver.call(this, sink);     // 再写回真实 sink
    };
    log("[RequestBody] hook installed");
  } catch(e) { log("RequestBody hook fail", e); }
});
