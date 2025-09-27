(function(){
  function log(){ try{ send({__frida_console:true, args:[].map.call(arguments, function(x){return ''+x;})}); }catch(e){} }
  try { log('[probe] Java.available =', (typeof Java!=='undefined')? Java.available:false); } catch(e){ log('[probe] err', e); }
  try {
    var mods = Process.enumerateModulesSync().slice(0,50).map(function(m){return m.name;});
    log('[probe-modules]', mods.join(', '));
  } catch(e){}
})();
