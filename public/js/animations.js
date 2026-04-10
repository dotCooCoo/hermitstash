// Scroll-triggered animations using data-anim attribute
// Same approach as test-anim.html which works
var animEls = document.querySelectorAll('[data-anim]');

if(animEls.length){
  var obs = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      if(entry.isIntersecting){
        entry.target.classList.add('in-view');
        obs.unobserve(entry.target);
      }
    });
  }, {threshold: 0.1});

  animEls.forEach(function(el){ obs.observe(el); });
}

// Scroll progress
var prog = document.getElementById('scrollProgress');
if(prog){
  var circle = prog.querySelector('.scroll-prog-circle');
  var circ = 2 * Math.PI * 20;
  window.addEventListener('scroll', function(){
    var pct = window.scrollY / (document.documentElement.scrollHeight - window.innerHeight);
    prog.classList.toggle('visible', pct > 0.05);
    if(circle) circle.style.strokeDashoffset = circ - (circ * pct);
  });
  prog.addEventListener('click', function(){ window.scrollTo({top:0, behavior:'smooth'}); });
}

// Parallax
var parallaxEls = document.querySelectorAll('[data-parallax]');
if(parallaxEls.length){
  window.addEventListener('scroll', function(){
    var y = window.scrollY;
    parallaxEls.forEach(function(el){
      el.style.transform = 'translateY(' + Math.round(y * (parseFloat(el.getAttribute('data-parallax')) || 0.3)) + 'px)';
    });
  });
}

// Counter
var counterEls = document.querySelectorAll('[data-count]');
if(counterEls.length){
  var cObs = new IntersectionObserver(function(entries){
    entries.forEach(function(entry){
      if(entry.isIntersecting){
        var el = entry.target;
        var target = el.getAttribute('data-count');
        if(/[A-Za-z]/.test(target)){ el.textContent = target; cObs.unobserve(el); return; }
        var num = parseInt(target, 10);
        if(isNaN(num)){ el.textContent = target; cObs.unobserve(el); return; }
        var t0 = performance.now();
        function step(now){
          var p = Math.min((now - t0) / 1500, 1);
          el.textContent = Math.round(num * (1 - Math.pow(1 - p, 3)));
          if(p < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
        cObs.unobserve(el);
      }
    });
  }, {threshold: 0.5});
  counterEls.forEach(function(el){ cObs.observe(el); });
}
