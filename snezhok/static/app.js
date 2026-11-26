const $=s=>document.querySelector(s),csrf=$('meta[name=csrf]')?.content;
function setTheme(t){localStorage.setItem('theme',t);document.documentElement.dataset.theme=t}
const th=$('#th');if(th)th.onclick=()=>setTheme(document.documentElement.dataset.theme=='dark'?'light':'dark');
for(let i=0;i<40;i++){const s=document.createElement('div');s.className='snow';s.textContent='❄';
s.style.cssText=`left:${Math.random()*100}vw;font-size:${8+Math.random()*14}px;animation-duration:${6+Math.random()*10}s;animation-delay:-${Math.random()*10}s`;document.body.appendChild(s)}
const pq=$('#pq');if(pq){let t;pq.oninput=()=>{clearTimeout(t);t=setTimeout(async()=>{$('#plist').innerHTML=await (await fetch('/api/people?q='+encodeURIComponent(pq.value))).text()},250)}}
const msgs=$('#msgs'),name=$('#chat')?.dataset.name;let since=-1,sig='',lastTyp=0;
const ago=s=>s<30?'в сети':s<3600?`был(а) ${Math.max(1,Math.floor(s/60))} мин назад`:s<86400?`был(а) ${Math.floor(s/3600)} ч назад`:'был(а) давно';
function beep(){try{const a=new AudioContext(),o=a.createOscillator(),g=a.createGain();o.connect(g);g.connect(a.destination);o.frequency.value=880;g.gain.setValueAtTime(.08,a.currentTime);g.gain.exponentialRampToValueAtTime(.001,a.currentTime+.25);o.start();o.stop(a.currentTime+.25)}catch(e){}}
function toast(n,t){const d=document.createElement('a');d.className='toast';d.href='/chat/'+encodeURIComponent(n);d.innerHTML='<b></b><span></span>';d.firstChild.textContent='✉ '+n;d.lastChild.textContent=t;$('#toast').appendChild(d);beep();setTimeout(()=>d.remove(),6000)}
async function refresh(){const h=await(await fetch(location.href)).text();const n=new DOMParser().parseFromString(h,'text/html').getElementById('msgs');
if(n&&n.innerHTML!=msgs.innerHTML){const old=msgs.children.length;msgs.innerHTML=n.innerHTML;[...msgs.children].slice(old).forEach(e=>e.classList.add('pop'));msgs.scrollTop=msgs.scrollHeight}}
async function poll(){try{const q=new URLSearchParams({since,vis:document.visibilityState=='visible'?1:0});if(name)q.set('chat',name);
const r=await(await fetch('/api/poll?'+q)).json();const b=$('#bdg');if(b){b.textContent=r.unread;b.style.display=r.unread?'inline-block':'none'}
document.title=(r.unread?`(${r.unread}) `:'')+'Снежок ❄';if(since>=0)r.new.forEach(m=>{if(m.name!=name)toast(m.name,m.body)});since=r.last;
if(name&&r.peer){const st=$('#st');st.className=r.peer.typing?'typ':r.peer.ago<30?'on':'';st.innerHTML=r.peer.typing?'печатает<i></i><i></i><i></i>':ago(r.peer.ago);if(r.sig!=sig){sig=r.sig;refresh()}}}catch(e){}}
if(csrf){poll();setInterval(poll,3000)}
const f=$('form.bar');if(f&&name){const inp=f.querySelector('input[name=body]');
inp.addEventListener('input',()=>{const n=Date.now();if(n-lastTyp>2000){lastTyp=n;const d=new FormData();d.append('csrf',csrf);d.append('to',name);fetch('/api/typing',{method:'POST',body:d})}});
f.addEventListener('submit',async e=>{e.preventDefault();if(!inp.value.trim())return;const fd=new FormData(f);inp.value='';await fetch(location.href,{method:'POST',body:fd});await refresh()});
msgs.scrollTop=msgs.scrollHeight}
if(csrf&&'serviceWorker' in navigator)navigator.serviceWorker.register('/sw.js');
const pb=$('#pushbtn');if(pb){const st=$('#pushst'),tb=$('#pushtest');
const ios=/iphone|ipad|ipod/i.test(navigator.userAgent),stand=navigator.standalone||matchMedia('(display-mode: standalone)').matches;
const u8=k=>Uint8Array.from(atob(k.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-k.length%4)%4)),c=>c.charCodeAt(0));
const post=(u,o)=>{const d=new FormData();d.append('csrf',csrf);for(const k in o)d.append(k,o[k]);return fetch(u,{method:'POST',body:d})};
(async()=>{if(!('serviceWorker' in navigator&&'PushManager' in window)){st.textContent=ios&&!stand?'Чтобы получать уведомления на iPhone: нажмите «Поделиться» → «На экран Домой», откройте Снежок с главного экрана и вернитесь в Настройки.':'Этот браузер не поддерживает уведомления.';return}
const reg=await navigator.serviceWorker.ready;let sub=await reg.pushManager.getSubscription();
const draw=()=>{st.textContent=sub?'Включены ✅ Когда вам напишут, а вы не в приложении, придёт уведомление.':'Выключены. Включите, чтобы получать сообщения, когда сайт закрыт.';pb.textContent=sub?'Выключить':'Включить уведомления';pb.style.display='inline-block';tb.style.display=sub?'inline-block':'none'};draw();
pb.onclick=async()=>{if(sub){await post('/api/push/unsubscribe',{endpoint:sub.endpoint});await sub.unsubscribe();sub=null;return draw()}
if(await Notification.requestPermission()!='granted'){st.textContent='Разрешение не выдано. Разрешите уведомления для Снежка в настройках телефона или браузера.';return}
const key=(await(await fetch('/api/push/key')).json()).key;sub=await reg.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:u8(key)});
await post('/api/push/subscribe',{sub:JSON.stringify(sub)});draw()};
tb.onclick=()=>post('/api/push/test',{})})()}
document.querySelectorAll('input[type=file]').forEach(i=>i.onchange=()=>{const s=i.parentElement.querySelector('span');const t=i.files[0]?'✓ '+i.files[0].name.slice(0,16):'Фото';if(s)s.textContent=t;else i.parentElement.firstChild.textContent=t+' '});
const rnd=$('#rnd');if(rnd)rnd.onclick=()=>{const a=["Снежный","Ледяной","Тёплый","Весёлый","Мягкий","Золотой","Добрый","Лесной"],n=["Олень","Пряник","Эльф","Носок","Мишка","Снегирь","Ёжик","Бубенец"],p=x=>x[Math.floor(Math.random()*x.length)];$('#nn').value=p(a)+'_'+p(n)+Math.floor(10+Math.random()*90)};
const nm=$('#nm');if(nm){const st=$('#nmst'),A=['Снежный','Пушистый','Ледяной','Весёлый','Мандариновый','Сказочный','Искристый','Хрустящий'],N=['Снеговик','Олень','Пингвин','Ёжик','Эльф','Пряник','Медвежонок','Хлопушка'];
const pick=a=>a[Math.floor(Math.random()*a.length)];let t;
async function chk(){const r=await(await fetch('/api/name?n='+encodeURIComponent(nm.value))).json();st.textContent=(r.ok?'✅ ':'❌ ')+r.msg;st.style.color=r.ok?'#35d07f':'#ff6b6b'}
nm.oninput=()=>{clearTimeout(t);t=setTimeout(chk,300)};
$('#dice').onclick=()=>{let n;do{n=pick(A)+pick(N)}while(n.length>20);if(n.length<=17)n+=Math.floor(Math.random()*90+10);nm.value=n;chk();const d=$('#dice');d.classList.remove('roll');void d.offsetWidth;d.classList.add('roll')}}
function confetti(){const c=['#e63946','#ffd23b','#3bff8a','#3b9bff','#ff7a59','#fff'];for(let i=0;i<70;i++){const e=document.createElement('i');e.className='cf';e.style.cssText=`left:${Math.random()*100}vw;background:${c[i%6]};animation-duration:${1.5+Math.random()*2}s;animation-delay:${Math.random()*.6}s;transform:rotate(${Math.random()*360}deg)`;document.body.appendChild(e);setTimeout(()=>e.remove(),4500)}}
if(document.querySelector('.flash')?.textContent.includes('🎉'))confetti();
