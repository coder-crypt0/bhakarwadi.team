// Wait for DOM to load
document.addEventListener('DOMContentLoaded', () => {
    
    // --- Custom Cursor ---
    const cursor = document.getElementById('custom-cursor');
    const follower = document.getElementById('cursor-follower');
    
    let posX = 0, posY = 0;
    let mouseX = 0, mouseY = 0;

    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        
        // Immediate update for the dot
        cursor.style.left = mouseX + 'px';
        cursor.style.top = mouseY + 'px';
    });

    // Smooth follower
    gsap.to({}, 0.016, {
        repeat: -1,
        onRepeat: () => {
            posX += (mouseX - posX) / 9;
            posY += (mouseY - posY) / 9;
            
            follower.style.left = posX + 'px';
            follower.style.top = posY + 'px';
        }
    });

    // Hover effects
    const links = document.querySelectorAll('a, button, .project-item, .team-card');
    links.forEach(link => {
        link.addEventListener('mouseenter', () => {
            document.body.classList.add('hovered');
        });
        link.addEventListener('mouseleave', () => {
            document.body.classList.remove('hovered');
        });
    });

    // --- Menu Toggle ---
    const menuBtn = document.querySelector('.menu-btn');
    const menuLinks = document.querySelectorAll('.menu-link');
    
    menuBtn.addEventListener('click', () => {
        document.body.classList.toggle('menu-open');
    });

    menuLinks.forEach(link => {
        link.addEventListener('click', () => {
            document.body.classList.remove('menu-open');
        });
    });

    // --- Loader ---
    const loaderBar = document.querySelector('.loader-progress');
    const loaderText = document.querySelector('.loader-text');
    
    let progress = 0;
    const interval = setInterval(() => {
        progress += Math.random() * 10;
        if (progress > 100) progress = 100;
        
        loaderBar.style.width = `${progress}%`;
        
        // Random tech text
        const texts = [
            "INITIALIZING BHAKARWADI PROTOCOL...",
            "LOADING SPICY ASSETS...",
            "COMPILING CAFFEINE...",
            "DECRYPTING SECRET SAUCE...",
            "OPTIMIZING CRUNCH FACTOR..."
        ];
        
        if (Math.random() > 0.7) {
            loaderText.innerText = texts[Math.floor(Math.random() * texts.length)];
        }

        if (progress === 100) {
            clearInterval(interval);
            setTimeout(() => {
                document.body.classList.add('loaded');
                initAnimations();
            }, 500);
        }
    }, 100);

    // --- Canvas Animation (Hero) ---
    const canvas = document.getElementById('hero-canvas');
    const ctx = canvas.getContext('2d');
    let width, height;
    let particles = [];

    function resize() {
        width = canvas.width = canvas.parentElement.offsetWidth;
        height = canvas.height = canvas.parentElement.offsetHeight;
    }
    
    window.addEventListener('resize', resize);
    resize();

    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 1;
            this.vy = (Math.random() - 0.5) * 1;
            this.size = Math.random() * 2 + 1;
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > width) this.vx *= -1;
            if (this.y < 0 || this.y > height) this.vy *= -1;
        }

        draw() {
            ctx.fillStyle = 'rgba(255, 87, 34, 0.5)'; // Accent color
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    for (let i = 0; i < 50; i++) {
        particles.push(new Particle());
    }

    function animateCanvas() {
        ctx.clearRect(0, 0, width, height);
        
        particles.forEach((p, index) => {
            p.update();
            p.draw();

            // Connect particles
            for (let j = index + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p.x - p2.x;
                const dy = p.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 150) {
                    ctx.strokeStyle = `rgba(255, 255, 255, ${0.1 - dist/1500})`;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }
        });

        requestAnimationFrame(animateCanvas);
    }
    animateCanvas();


    // --- Scramble Text Function ---
    // REMOVED AS PER REQUEST

    // --- GSAP Animations ---
    function initAnimations() {
        gsap.registerPlugin(ScrollTrigger);

        // Hero Text Reveal
        gsap.from(".hero-content h1", {
            y: 100,
            opacity: 0,
            duration: 1.5,
            stagger: 0.2,
            ease: "power4.out",
            delay: 0.5
        });

        gsap.from(".hero-subtitle", {
            y: 50,
            opacity: 0,
            duration: 1,
            ease: "power3.out",
            delay: 1.2
        });

        // Section Headers
        gsap.utils.toArray('.section-header').forEach(header => {
            gsap.from(header, {
                scrollTrigger: {
                    trigger: header,
                    start: "top 80%",
                },
                x: -50,
                opacity: 0,
                duration: 1
            });
        });

        // Text Reveal
        gsap.utils.toArray('.reveal-text p').forEach(text => {
            gsap.from(text, {
                scrollTrigger: {
                    trigger: text,
                    start: "top 85%",
                },
                y: 30,
                opacity: 0,
                duration: 1
            });
        });

        // Number Counter
        gsap.utils.toArray('.stat-item').forEach(stat => {
            const counter = stat.querySelector('.count');
            const target = parseInt(counter.getAttribute('data-target'));
            
            ScrollTrigger.create({
                trigger: stat,
                start: "top 80%",
                once: true,
                onEnter: () => {
                    gsap.to(counter, {
                        innerHTML: target,
                        duration: 2,
                        snap: { innerHTML: 1 },
                        ease: "power1.inOut"
                    });
                }
            });
        });

        // Team Cards Stagger
        gsap.from(".team-card", {
            scrollTrigger: {
                trigger: ".team-grid",
                start: "top 75%",
            },
            y: 100,
            opacity: 0,
            duration: 1,
            stagger: 0.2,
            ease: "power3.out"
        });

        // Manifesto Items
        gsap.from(".manifesto-item", {
            scrollTrigger: {
                trigger: ".manifesto-content",
                start: "top 75%",
            },
            y: 50,
            opacity: 0,
            duration: 0.8,
            stagger: 0.2,
            ease: "back.out(1.7)"
        });

        // Mobile Tear Effect (Parallax) - REVISED
        if (window.innerWidth <= 768) {
            gsap.utils.toArray('.mobile-tear').forEach((section, i) => {
                // Remove the rotation, add a scale/fade up effect
                gsap.fromTo(section, 
                    { 
                        scale: 0.95, 
                        opacity: 0.8,
                        y: 50 
                    },
                    {
                        scrollTrigger: {
                            trigger: section,
                            start: "top 90%",
                            end: "top 60%",
                            scrub: 1
                        },
                        scale: 1,
                        opacity: 1,
                        y: 0,
                        ease: "power2.out"
                    }
                );
            });
        }

        // Project Items
        gsap.utils.toArray('.project-item').forEach(item => {
            gsap.from(item, {
                scrollTrigger: {
                    trigger: item,
                    start: "top 85%",
                },
                x: -50,
                opacity: 0,
                duration: 1,
                ease: "power2.out"
            });
        });
    }

    // --- Infinite Draggable Testimonials ---
    const wrapper = document.querySelector(".testimonial-wrapper");
    const track = document.querySelector(".testimonial-track");
    const cards = gsap.utils.toArray(".testimonial-card");
    
    // Calculate total width of one set of cards (assuming 3 sets)
    // We need to make sure we have enough content to scroll seamlessly
    
    let loop = horizontalLoop(cards, {
        paused: false,
        repeat: -1,
        speed: 1, // Speed of the auto-scroll
        paddingRight: 50 // Match the gap in CSS
    });

    // Add Draggable
    Draggable.create(".testimonial-track", {
        type: "x",
        trigger: ".testimonial-wrapper",
        inertia: true,
        onPress: () => loop.pause(),
        onRelease: () => loop.play(),
        onDrag: function() {
            // Update the loop based on drag amount
            // This is a simplified integration. For perfect sync, we'd need a more complex setup
            // But for this effect, we can just let Draggable move the track and then reset
        },
        onThrowUpdate: function() {
             // Syncing Draggable with the loop is complex. 
             // Instead, we will use a simpler approach: 
             // Let the loop handle the movement, and Draggable just modifies the timeScale or progress.
        }
    });
    
    // Since syncing Draggable directly with a seamless loop helper is tricky without the paid InertiaPlugin sometimes,
    // We will use a simpler "Hover to Pause, Drag to Scroll" approach or just the helper's built-in draggable support if available.
    
    // Actually, the helper function 'horizontalLoop' (standard GSAP helper) supports draggable integration if we code it.
    // Let's use a robust implementation of horizontalLoop below.

    /*
    This helper function makes a group of elements animate along the x-axis in a seamless, responsive loop.
    Features:
     - Uses xPercent so that even if the widths change (like if the window gets resized), it should still work in most cases.
     - When each item animates to the left or right enough, it will loop back to the other side
     - Optional "speed" parameter allows you to control the speed
     - Pausing, reversing, playing, and timeScale are all supported
    */
    function horizontalLoop(items, config) {
        items = gsap.utils.toArray(items);
        config = config || {};
        let tl = gsap.timeline({repeat: config.repeat, paused: config.paused, defaults: {ease: "none"}, onReverseComplete: () => tl.totalTime(tl.rawTime() + tl.duration() * 100)}),
            length = items.length,
            startX = items[0].offsetLeft,
            times = [],
            widths = [],
            xPercents = [],
            curIndex = 0,
            pixelsPerSecond = (config.speed || 1) * 100,
            snap = config.snap === false ? v => v : gsap.utils.snap(config.snap || 1), // some browsers shift by a pixel to accommodate flex layouts, so for example if width is 20% the first element's width might be 242px, and the next 243px, alternating back and forth. So we snap to 5 percentage points to make things look more natural
            totalWidth, curX, distanceToStart, distanceToLoop, item, i;
        
        gsap.set(items, { // convert "x" to "xPercent" to make things responsive, and populate the widths/xPercents Arrays to make lookups faster.
            xPercent: (i, el) => {
                let w = widths[i] = parseFloat(gsap.getProperty(el, "width", "px"));
                xPercents[i] = snap(parseFloat(gsap.getProperty(el, "x", "px")) / w * 100 + gsap.getProperty(el, "xPercent"));
                return xPercents[i];
            }
        });
        gsap.set(items, {x: 0});
        
        totalWidth = items[length-1].offsetLeft + xPercents[length-1] / 100 * widths[length-1] - startX + items[length-1].offsetWidth * gsap.getProperty(items[length-1], "scaleX") + (parseFloat(config.paddingRight) || 0);
        
        for (i = 0; i < length; i++) {
            item = items[i];
            curX = xPercents[i] / 100 * widths[i];
            distanceToStart = item.offsetLeft + curX - startX;
            distanceToLoop = distanceToStart + widths[i] * gsap.getProperty(item, "scaleX");
            tl.to(item, {xPercent: snap((curX - distanceToLoop) / widths[i] * 100), duration: distanceToLoop / pixelsPerSecond}, 0)
              .fromTo(item, {xPercent: snap((curX - distanceToLoop + totalWidth) / widths[i] * 100)}, {xPercent: xPercents[i], duration: (curX - distanceToLoop + totalWidth - curX) / pixelsPerSecond, immediateRender: false}, distanceToLoop / pixelsPerSecond)
              .add("label" + i, distanceToStart / pixelsPerSecond);
            times[i] = distanceToStart / pixelsPerSecond;
        }
        
        function toIndex(index, vars) {
            vars = vars || {};
            (Math.abs(index - curIndex) > length / 2) && (index += index > curIndex ? -length : length); // always go in the shortest direction
            let newIndex = gsap.utils.wrap(0, length, index),
                time = times[newIndex];
            if (time > tl.time() !== index > curIndex) { // if we're wrapping the timeline's playhead, make the proper adjustments
                vars.modifiers = {time: gsap.utils.wrap(0, tl.duration())};
                time += tl.duration() * (index > curIndex ? 1 : -1);
            }
            curIndex = newIndex;
            vars.overwrite = true;
            return tl.tweenTo(time, vars);
        }
        
        tl.next = vars => toIndex(curIndex+1, vars);
        tl.previous = vars => toIndex(curIndex-1, vars);
        tl.current = () => curIndex;
        tl.toIndex = (index, vars) => toIndex(index, vars);
        tl.times = times;
        tl.progress(1, true).progress(0, true); // pre-render for performance
        
        if (config.reversed) {
            tl.vars.onReverseComplete();
            tl.reverse();
        }
        
        // Draggable Integration
        const proxy = document.createElement("div");
        let slideAnimation = gsap.to({}, {duration: 0.1}); // placeholder
        let draggable = Draggable.create(proxy, {
            trigger: ".testimonial-wrapper",
            type: "x",
            inertia: true,
            onPress: function() {
                tl.pause();
                slideAnimation.kill();
            },
            onDrag: function() {
                let delta = this.x - this.startX;
                tl.time(tl.time() - delta / pixelsPerSecond * 2); // *2 for sensitivity
                this.startX = this.x;
            },
            onRelease: function() {
                tl.play();
            }
        })[0];

        return tl;
    }

    // --- Magnetic Button Effect ---
    const magnets = document.querySelectorAll('.magnetic-btn');
    magnets.forEach(magnet => {
        magnet.addEventListener('mousemove', (e) => {
            const rect = magnet.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            gsap.to(magnet, {
                x: x * 0.3,
                y: y * 0.3,
                duration: 0.3
            });
        });

        magnet.addEventListener('mouseleave', () => {
            gsap.to(magnet, {
                x: 0,
                y: 0,
                duration: 0.5,
                ease: "elastic.out(1, 0.3)"
            });
        });
    });

});
