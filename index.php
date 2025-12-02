<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Team Bhakarwadi | Engineering Chaos</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syncopate:wght@400;700&family=Outfit:wght@300;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="loading">

    <div id="custom-cursor"></div>
    <div id="cursor-follower"></div>

    <div id="loader">
        <div class="loader-content">
            <span class="loader-text">INITIALIZING BHAKARWADI PROTOCOL</span>
            <div class="loader-bar"><div class="loader-progress"></div></div>
        </div>
    </div>

    <div id="noise-overlay"></div>

    <nav>
        <div class="logo">BHAKARWADI<span class="dot">.</span>TEAM</div>
        <div class="menu-btn">
            <div class="menu-text">MENU</div>
            <div class="burger">
                <span></span>
                <span></span>
            </div>
        </div>
    </nav>

    <div id="menu-overlay">
        <div class="menu-links">
            <a href="#hero" class="menu-link" data-text="HOME">HOME</a>
            <a href="#about" class="menu-link" data-text="ORIGIN">ORIGIN</a>
            <a href="#squad" class="menu-link" data-text="SQUAD">SQUAD</a>
            <a href="#projects" class="menu-link" data-text="ARSENAL">ARSENAL</a>
            <a href="#manifesto" class="menu-link" data-text="MANIFESTO">MANIFESTO</a>
            <a href="#footer" class="menu-link" data-text="CONTACT">CONTACT</a>
        </div>
        <div class="menu-decoration">
            <span>SYSTEM STATUS: ONLINE</span>
            <span>ENCRYPTION: ENABLED</span>
        </div>
    </div>

    <main id="smooth-wrapper">
        <div id="smooth-content">
            
            <section id="hero" class="section">
                <div class="hero-content">
                    <h1 class="glitch" data-text="WE ARE">WE ARE</h1>
                    <h1 class="glitch large" data-text="BHAKARWADI">BHAKARWADI</h1>
                    <p class="hero-subtitle">Crunchy on the outside. Spicy on the inside. Turing-complete everywhere.</p>
                    <div class="scroll-indicator">
                        <span>SCROLL TO DECRYPT</span>
                        <div class="line"></div>
                    </div>
                </div>
                <div class="hero-visual">
                    <!-- Canvas animation will go here -->
                    <canvas id="hero-canvas"></canvas>
                </div>
            </section>

            <div class="tear-separator"></div>

            <section id="about" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">01</span>
                        <h2>THE ORIGIN</h2>
                    </div>
                    <div class="about-grid">
                        <div class="text-block reveal-text">
                            <p>Named after Pune's legendary spiral snack, we are a team of 4 engineers who believe code should be as layered and spicy as a Bhakarwadi.</p>
                            <p>We don't just write software; we craft digital experiences that confuse regular people and impress the ones who check the 'Inspect Element'.</p>
                        </div>
                        <div class="stat-block">
                            <div class="stat-item">
                                <span class="count" data-target="4">0</span>
                                <span class="label">Humans</span>
                            </div>
                            <div class="stat-item">
                                <span class="count" data-target="10000">0</span>
                                <span class="label">Caffeine Units</span>
                            </div>
                            <div class="stat-item">
                                <span class="count" data-target="404">0</span>
                                <span class="label">Sleep Not Found</span>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            <div class="tear-separator"></div>

            <section id="manifesto" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">02</span>
                        <h2>THE MANIFESTO</h2>
                    </div>
                    <div class="manifesto-content">
                        <div class="manifesto-item">
                            <h3>01. CHAOS IS A LADDER</h3>
                            <p>If the code isn't slightly terrifying to look at, is it really engineering? We embrace the entropy.</p>
                        </div>
                        <div class="manifesto-item">
                            <h3>02. SPICE LEVEL: CRITICAL</h3>
                            <p>Bland UIs are for accountants. We serve visuals that burn (in a good way).</p>
                        </div>
                        <div class="manifesto-item">
                            <h3>03. DEPLOY ON FRIDAYS</h3>
                            <p>We like to live dangerously. It keeps the adrenaline pumping and the servers guessing.</p>
                        </div>
                    </div>
                </div>
            </section>

            <section id="squad" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">03</span>
                        <h2>THE SQUAD</h2>
                    </div>
                    <div class="team-grid">
                        <?php
                        $team = [
                            [
                                'name' => 'Ritik Arora',
                                'role' => 'Full Stack Overlord',
                                'desc' => 'Can center a div in 3 dimensions. Speaks fluent binary and sarcasm.'
                            ],
                            [
                                'name' => 'Arya Chavan',
                                'role' => 'Algorithm Alchemist',
                                'desc' => 'Turns coffee into O(1) complexity solutions. Probably dreaming in Python right now.'
                            ],
                            [
                                'name' => 'Alesha Mulla',
                                'role' => 'Pixel Perfector',
                                'desc' => 'Sees the world in hex codes. Will judge your font pairing choices silently.'
                            ],
                            [
                                'name' => 'Abhishek Saraf',
                                'role' => 'System Architect',
                                'desc' => 'Builds backends so robust they survive nuclear winters. Fears no merge conflict.'
                            ]
                        ];

                        foreach ($team as $member) {
                            echo '<div class="team-card tilt-card">';
                            echo '<div class="card-inner">';
                            echo '<h3>' . $member['name'] . '</h3>';
                            echo '<span class="role">[' . $member['role'] . ']</span>';
                            echo '<p>' . $member['desc'] . '</p>';
                            echo '</div>';
                            echo '</div>';
                        }
                        ?>
                    </div>
                </div>
            </section>

            <section id="projects" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">04</span>
                        <h2>THE ARSENAL</h2>
                    </div>
                    <div class="project-list">
                        <?php
                        $projects = [
                            [
                                'name' => 'Daquiri',
                                'tag' => 'PATENTED TECH',
                                'desc' => 'A Data Acquisition System for the automotive industry so advanced it knows your car is breaking down before you do. Yes, it\'s patented. We are fancy like that.'
                            ],
                            [
                                'name' => 'TORnado',
                                'tag' => 'PRIVACY MAX',
                                'desc' => 'A TOR-based messaging platform. Because sometimes you need to whisper so quietly even the ISP can\'t hear you. CLI for the hackers, GUI for the slackers.'
                            ],
                            [
                                'name' => 'NoSQL2SQL',
                                'tag' => 'DATABASE WIZARDRY',
                                'desc' => 'The holy grail of database migration. Converts unstructured chaos (NoSQL) into structured order (SQL). It\'s basically therapy for your data.'
                            ],
                            [
                                'name' => 'Crakrr',
                                'tag' => 'SECURITY OPS',
                                'desc' => 'Web-vulnerability assessment tool with Kali Linux tools integrated. It finds holes in your security faster than you find holes in our logic.'
                            ],
                            [
                                'name' => 'Microstic',
                                'tag' => 'AI / ML',
                                'desc' => 'ML-powered microplastic detection. Saving the oceans one pixel at a time. Fish love us.'
                            ],
                            [
                                'name' => 'PathFinder',
                                'tag' => 'VISUALIZATION',
                                'desc' => 'Visualizing pathfinding algorithms in 2D and 3D. Watching Dijkstra run is our version of Netflix and Chill.'
                            ]
                        ];

                        foreach ($projects as $index => $project) {
                            echo '<div class="project-item" data-index="0' . ($index + 1) . '">';
                            echo '<div class="project-info">';
                            echo '<span class="project-tag">' . $project['tag'] . '</span>';
                            echo '<h3>' . $project['name'] . '</h3>';
                            echo '<p>' . $project['desc'] . '</p>';
                            echo '</div>';
                            echo '<div class="project-visual"></div>'; // JS will inject cool stuff here
                            echo '</div>';
                        }
                        ?>
                    </div>
                </div>
            </section>

            <section id="testimonials" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">05</span>
                        <h2>STREET CRED</h2>
                    </div>
                    <div class="testimonial-wrapper">
                        <div class="testimonial-track">
                            <?php
                            $testimonials = [
                                ["text" => "I asked them to center a div, and they built a 3D rendering engine instead. 10/10 would get confused again.", "author" => "A Very Confused Client"],
                                ["text" => "Their code is so clean it makes my soap look dirty.", "author" => "Clean Code Bob"],
                                ["text" => "Bhakarwadi Team? More like StackOverflow's worst nightmare.", "author" => "Anonymous Senior Dev"],
                                ["text" => "I tried to hack them, but I just got a recipe for Bhakarwadi.", "author" => "Script Kiddie"],
                                ["text" => "The animations are so smooth I slipped and fell.", "author" => "UI Designer"]
                            ];
                            
                            // Duplicate for infinite loop
                            $all_testimonials = array_merge($testimonials, $testimonials, $testimonials);

                            foreach ($all_testimonials as $t) {
                                echo '<div class="testimonial-card">';
                                echo '<p>"' . $t['text'] . '"</p>';
                                echo '<span>- ' . $t['author'] . '</span>';
                                echo '</div>';
                            }
                            ?>
                        </div>
                    </div>
                </div>
            </section>

            <section id="tech-stack" class="section mobile-tear">
                <div class="container">
                    <div class="section-header">
                        <span class="section-number">06</span>
                        <h2>THE TOOLKIT</h2>
                    </div>
                    <div class="tech-grid">
                        <div class="tech-item"><span>PHP</span></div>
                        <div class="tech-item"><span>JavaScript</span></div>
                        <div class="tech-item"><span>Python</span></div>
                        <div class="tech-item"><span>React</span></div>
                        <div class="tech-item"><span>Node.js</span></div>
                        <div class="tech-item"><span>Docker</span></div>
                        <div class="tech-item"><span>Kali Linux</span></div>
                        <div class="tech-item"><span>Coffee</span></div>
                    </div>
                </div>
            </section>

            <section id="footer" class="section">
                <div class="container">
                    <h2 class="footer-text">READY TO <br> COLLABORATE?</h2>
                    <div class="contact-links">
                        <a href="#" class="magnetic-btn">Get in Touch</a>
                        <a href="#" class="magnetic-btn">Send Snacks</a>
                    </div>
                    <div class="footer-bottom">
                        <p>&copy; <?php echo date("Y"); ?> Team Bhakarwadi. All rights reserved.</p>
                        <p>Made with <span class="heart">♥</span> and spicy spirals.</p>
                    </div>
                </div>
            </section>

        </div>
    </main>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/ScrollTrigger.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/Draggable.min.js"></script>
    <script src="js/script.js"></script>
</body>
</html>