function setTheme(t){localStorage.setItem('theme',t);document.documentElement.dataset.theme=t}
const th=document.getElementById('th');if(th)th.onclick=()=>setTheme(document.documentElement.dataset.theme=='dark'?'light':'dark');
for(let i=0;i<40;i++){const s=document.createElement('div');s.className='snow';s.textContent='❄';
s.style.cssText=`left:${Math.random()*100}vw;font-size:${8+Math.random()*14}px;animation-duration:${6+Math.random()*10}s;animation-delay:-${Math.random()*10}s`;document.body.appendChild(s)}
const m=document.getElementById('msgs');if(m){m.scrollTop=m.scrollHeight;setInterval(async()=>{if(document.activeElement.value)return;
const h=await (await fetch(location.href)).text();const n=new DOMParser().parseFromString(h,'text/html').getElementById('msgs');if(n&&n.innerHTML!=m.innerHTML){m.innerHTML=n.innerHTML;m.scrollTop=m.scrollHeight}},4000)}
const pq=document.getElementById('pq');if(pq){let t;pq.oninput=()=>{clearTimeout(t);t=setTimeout(async()=>{document.getElementById('plist').innerHTML=await (await fetch('/api/people?q='+encodeURIComponent(pq.value))).text()},250)}}
