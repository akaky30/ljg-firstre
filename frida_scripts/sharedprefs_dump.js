Java.perform(function() {
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }
  try {
    var SPImpl = Java.use('android.app.SharedPreferencesImpl');
    var EditorImpl = Java.use('android.app.SharedPreferencesImpl$EditorImpl');

    function whichFile(sp) {
      try {
        var f = sp.getClass().getDeclaredField('mFile');
        f.setAccessible(true);
        var file = f.get(sp);
        return file ? file.getAbsolutePath() : '(unknown-file)';
      } catch(e) { return '(unknown-file)'; }
    }

    if (SPImpl.getAll) {
      var getAll = SPImpl.getAll.overload();
      getAll.implementation = function() {
        var ret = getAll.call(this);
        try { log('[SharedPreferences][getAll] file=', whichFile(this), ' -> ', ret.toString()); } catch(e){}
        return ret;
      };
    }
    if (SPImpl.getString) {
      var getStr = SPImpl.getString.overload('java.lang.String','java.lang.String');
      getStr.implementation = function(key, def) {
        var v = getStr.call(this, key, def);
        try { log('[SharedPreferences][getString] file=', whichFile(this), ' ', key, ' = ', v); } catch(e){}
        return v;
      };
    }

    function hookEditor(name, sig) {
      try {
        var ov = EditorImpl[name].overload.apply(EditorImpl[name], sig);
        ov.implementation = function() {
          try {
            if (name.startsWith('put')) {
              log('[SharedPreferences][Editor.'+name+']', arguments[0], '=', arguments[1]);
            } else if (name === 'remove') {
              log('[SharedPreferences][Editor.remove] key=', arguments[0]);
            } else if (name === 'clear') {
              log('[SharedPreferences][Editor.clear]');
            } else if (name === 'apply' || name === 'commit') {
              log('[SharedPreferences][Editor.'+name+']');
            }
          } catch(e){}
          return ov.apply(this, arguments);
        };
      } catch(e){}
    }

    hookEditor('putString', ['java.lang.String','java.lang.String']);
    hookEditor('putInt', ['java.lang.String','int']);
    hookEditor('putLong', ['java.lang.String','long']);
    hookEditor('putFloat', ['java.lang.String','float']);
    hookEditor('putBoolean', ['java.lang.String','boolean']);
    hookEditor('remove', ['java.lang.String']);
    hookEditor('clear', []);
    hookEditor('apply', []);
    hookEditor('commit', []);

    log('[SharedPreferences] hooks installed');
  } catch(e) { log('sharedprefs_dump err:', e); }
});
