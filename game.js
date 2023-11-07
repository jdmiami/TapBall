// Constants
const BALL_SIZE_INITIAL = 100;
const BALL_COLOR_INITIAL = 0xff0000;
const MENU_BUTTON_COLOR = 0xff0000;
const SPEED_TEXT_STYLE = { fontSize: '50px', fill: '#fff', align: 'right', fontWeight: 'bold' };
const SCORE_TEXT_STYLE = { fontSize: '500px', fill: '#fff', align: 'center' };
const BUTTON_RECT_DIMENSIONS = { width: 50, height: 50 };

// State Management
const gameState = {
  score: 0,
  ballSize: BALL_SIZE_INITIAL,
  ballColor: BALL_COLOR_INITIAL,
  menuOpen: false,
  speed: 0,
  maxSpeed: 200
};

// Reusable Functions
function createBallTexture(size, color) {
  const graphics = this.add.graphics();
  graphics.fillStyle(color);
  graphics.fillCircle(size, size, size);
  const textureName = `ballTexture${gameState.score}`;
  graphics.generateTexture(textureName, size * 2, size * 2);
  graphics.destroy();
  return textureName;
}

function resizeGameElements() {
  const w = window.innerWidth;
  const h = window.innerHeight;

  game.renderer.resize(w, h);
  game.physics.world.setBounds(0, 0, w, h);

  ball.setPosition(w / 2, h / 2);
  scoreText.setPosition(w / 2, h / 2);
  speedText.setPosition(w - 10, 10);

  buttonRect.setSize(BUTTON_RECT_DIMENSIONS.width, BUTTON_RECT_DIMENSIONS.height);
  buttonRect.setPosition(w - BUTTON_RECT_DIMENSIONS.width - 10, h - BUTTON_RECT_DIMENSIONS.height - 10);
}

function updateBallShadow() {
  ballShadow.clear();
  ballShadow.fillStyle(0xffffff, 1);
  ballShadow.fillCircle(ball.x + 10, ball.y + 10, gameState.ballSize);
}

function changeBallProperties() {
  gameState.ballSize *= 0.98;
  gameState.ballColor = Phaser.Display.Color.RandomRGB().color;

  const textureName = createBallTexture.call(this, gameState.ballSize, gameState.ballColor);

  ball.setTexture(textureName);
  ball.displayWidth = gameState.ballSize * 2;
  ball.displayHeight = gameState.ballSize * 2;
  
  ball.body.setSize(ball.displayWidth, ball.displayHeight);

  updateBallShadow();

  ball.setTint(0xffffff);
  setTimeout(() => {
      ball.clearTint();
  }, 250);
}

function resetBallProperties() {
  gameState.ballSize = BALL_SIZE_INITIAL;
  gameState.ballColor = BALL_COLOR_INITIAL;
  ball.clearTint();
  
  const textureName = createBallTexture.call(this, gameState.ballSize, gameState.ballColor);

  ball.setTexture(textureName);
  ball.displayWidth = gameState.ballSize * 2;
  ball.displayHeight = gameState.ballSize * 2;

  updateBallShadow();
}

function onPointerDown(pointer) {
  const dx = pointer.x - ball.x;
  const dy = pointer.y - ball.y;

  if (dx * dx + dy * dy <= gameState.ballSize * gameState.ballSize) {
      // Generate a random angle in radians
      const randomAngle = Phaser.Math.FloatBetween(0, 2 * Math.PI);
      const speed = gameState.score === 0 ? gameState.maxSpeed : gameState.speed * 1.03;
      
      // Convert the angle to a direction vector
      const directionX = Math.cos(randomAngle);
      const directionY = Math.sin(randomAngle);

      ball.setVelocity(directionX * speed, directionY * speed);

      gameState.score++;
      scoreText.setText(gameState.score.toString());
      changeBallProperties.bind(this)();
  } else {
      gameState.score = 0;
      scoreText.setText(gameState.score.toString());
      ball.setPosition(window.innerWidth / 2, window.innerHeight / 2);
      ball.setVelocity(0, 0);
      resetBallProperties.bind(this)();
  }
}

// Phaser Game Configuration
var config = {
  type: Phaser.AUTO,
  width: window.innerWidth,
  height: window.innerHeight,
  physics: {
      default: 'arcade',
      arcade: {
          gravity: { y: 0 }
      }
  },
  scene: {
      create: create,
      update: update
  }
};

var game = new Phaser.Game(config);
var ball;
var ballShadow;
var scoreText;
var speedText;
var menu;
var buttonRect;

function create() {
  ballShadow = this.add.graphics({ fillStyle: { color: 0xffffff, alpha: 1 } });
  ballShadow.fillCircle(window.innerWidth / 2, window.innerHeight / 2, BALL_SIZE_INITIAL);

  ball = this.physics.add.image(window.innerWidth / 2, window.innerHeight / 2, createBallTexture.call(this, BALL_SIZE_INITIAL, BALL_COLOR_INITIAL));

  ball.setCollideWorldBounds(true);
  ball.setBounce(1, 1);
  ball.setVelocity(0, 0);

  scoreText = this.add.text(window.innerWidth / 2, window.innerHeight / 2, '0', SCORE_TEXT_STYLE).setOrigin(0.5);
  scoreText.setDepth(-1);

  buttonRect = new Phaser.Geom.Rectangle(window.innerWidth - 60, window.innerHeight - 60, 50, 50);

  // Menu button
  const button = this.add.graphics({ fillStyle: { color: MENU_BUTTON_COLOR } });
  button.fillRectShape(buttonRect);
  button.setInteractive(buttonRect, Phaser.Geom.Rectangle.Contains);
  button.on('pointerdown', openMenu, this);

  // Menu DOM element
  menu = this.add.dom(window.innerWidth / 2, window.innerHeight / 2).createFromCache('menu');

  window.addEventListener('resize', resizeGameElements.bind(this), false);

  speedText = this.add.text(window.innerWidth - 10, 10, 'Speed: 0', SPEED_TEXT_STYLE).setOrigin(1, 0);

  this.input.on('pointerdown', onPointerDown.bind(this), this);
}

function update() {
  gameState.speed = Math.sqrt(ball.body.velocity.x * ball.body.velocity.x + ball.body.velocity.y * ball.body.velocity.y);
  gameState.maxSpeed = 200 + gameState.score * 20;

  if (gameState.speed > gameState.maxSpeed) {
      ball.body.velocity.x *= gameState.maxSpeed / gameState.speed;
      ball.body.velocity.y *= gameState.maxSpeed / gameState.speed;
  }

  speedText.setText('Speed: ' + Math.round(gameState.speed));

  updateBallShadow();

  if (Phaser.Geom.Rectangle.ContainsPoint(buttonRect, ball)) {
    ball.setTint(MENU_BUTTON_COLOR);
  } else {
    ball.clearTint();
  }
}

function openMenu() {
  // Toggle the menu state
  gameState.menuOpen = !gameState.menuOpen;

  // Pause or resume the game based on the menu state
  if (gameState.menuOpen) {
    // Pause the game physics and all the tweens
    this.physics.pause();
    this.tweens.pauseAll();

    // Set the menu visibility to true and ensure it's on top of the game
    menu.setVisible(true);
    menu.setDepth(100); // Ensure the menu is above all other game objects

    // If the menu is a Phaser DOM element, apply styles directly
    // If it's an HTML element styled with CSS, ensure the CSS has high contrast colors and is visible
    menu.setAlpha(1); // Make sure the menu is fully opaque

    // If there are other game elements or logic that need to be paused, handle them here
    // For example, pausing a game timer or disabling input
  } else {
    // Resume the game physics and all the tweens
    this.physics.resume();
    this.tweens.resumeAll();

    // Set the menu visibility to false
    menu.setVisible(false);

    // Resume other game elements or logic that were paused
  }
}

