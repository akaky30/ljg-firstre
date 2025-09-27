Java.perform(function () {
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }

  var TARGET = "{class_name}";
  var INCLUDE_STATIC = {include_static};      // true/false
  var INCLUDE_INSTANCE = {include_instance};  // true/false
  var FIELDS_FILTER = "{fields_filter}";      // 逗号分隔关键词，可为空
  log("[dump] target class:", TARGET);

  // 选择能加载该类的 ClassLoader
  try {
    var loaders = Java.enumerateClassLoadersSync();
    var picked = null;
    for (var i = 0; i < loaders.length; i++) {
      var L = loaders[i];
      try { if (L.findClass && L.findClass(TARGET)) { picked = L; break; } } catch(_){}
      try { if (L.loadClass && L.loadClass(TARGET, false)) { picked = L; break; } } catch(_){}
    }
    if (picked) { Java.classFactory.loader = picked; log("[dump] picked loader:", picked.$className || picked.toString()); }
  } catch(e){}

  function matchFilter(name){
    if (!FIELDS_FILTER) return true;
    try{
      var arr = FIELDS_FILTER.split(",").map(function(s){return s.trim();}).filter(Boolean);
      if (!arr.length) return true;
      for (var i=0;i<arr.length;i++){ if (name.indexOf(arr[i]) >= 0) return true; }
      return false;
    }catch(e){ return true; }
  }

  // 静态字段
  var Clz, Modifier;
  try {
    Clz = Java.use(TARGET);
    Modifier = Java.use("java.lang.reflect.Modifier");
    var fields = Clz.class.getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
      try {
        var f = fields[i]; f.setAccessible(true);
        var isStatic = Modifier.isStatic(f.getModifiers());
        var isString = f.getType().getName() === "java.lang.String";
        if (isString && isStatic && INCLUDE_STATIC && matchFilter(f.getName())) {
          var val = f.get(null);
          log("[DUMP][static]", TARGET + "." + f.getName(), "=", val);
        }
      } catch (eF) {}
    }
  } catch (eClz) {
    log("[dump] ERROR: cannot use class:", eClz);
  }

  // 实例字段
  if (INCLUDE_INSTANCE) {
    var found = false;
    Java.choose(TARGET, {
      onMatch: function (inst) {
        found = true;
        try {
          var flds = inst.getClass().getDeclaredFields();
          var Modifier = Java.use('java.lang.reflect.Modifier');
          for (var i = 0; i < flds.length; i++) {
            try {
              flds[i].setAccessible(true);
              var isStatic = Modifier.isStatic(flds[i].getModifiers());
              var isString = flds[i].getType().getName() === "java.lang.String";
              if (isString && !isStatic && matchFilter(flds[i].getName())) {
                var v = flds[i].get(inst);
                log("[DUMP][instance]", TARGET + "#" + flds[i].getName(), "=", v);
              }
            } catch (e1) {}
          }
        } catch (e2) {}
      },
      onComplete: function () { if (!found) log("[dump] no instance found for", TARGET); log("[dump] choose complete for", TARGET); }
    });
  }
});
