Java.perform(function(){
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Buffer = Java.use('okio.Buffer');
        var RequestBody = Java.use('okhttp3.RequestBody');
        var newCall_over = OkHttpClient.newCall.overload('okhttp3.Request');

        newCall_over.implementation = function(request){
            try {
                var url = "(unknown)"; try { url = request.url().toString(); } catch(e){}
                console.log("[okhttp hook] url=" + url);
                try {
                    var body = request.body();
                    if (body) {
                        var buf = Buffer.$new();
                        body.writeTo(buf);
                        var bytes = buf.readByteArray();
                        var Base64 = Java.use('android.util.Base64');
                        console.log("[okhttp hook][body][base64] " + Base64.encodeToString(bytes, 0));
                    }
                } catch(e){}
                return newCall_over.call(this, request);
            } catch(inner){
                try { return newCall_over.call(this, request); } catch(e){ return this.newCall(request); }
            }
        };
        console.log("[okhttp hook] installed");
    } catch(e){
        console.log("[okhttp hook] install failed: " + e);
    }
});