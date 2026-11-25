self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(clients.claim()));
self.addEventListener('push',e=>{let d={};try{d=e.data.json()}catch(x){}
e.waitUntil(self.registration.showNotification(d.title||'Снежок ❄',{body:d.body||'Новое сообщение',icon:'/static/icon-192.png',badge:'/static/icon-192.png',tag:d.tag,renotify:true,data:{url:d.url||'/'}}))});
self.addEventListener('notificationclick',e=>{e.notification.close();const u=e.notification.data.url;
e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('navigate' in c){c.navigate(u);return c.focus()}}return clients.openWindow(u)}))});
