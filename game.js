/**
 * Configures the Phaser game instance.
 * Sets up the game to run in AUTO mode with no gravity. 
 * Configures the game width/height to match the browser window size.
 * Adds 'create' and 'update' scene methods.
*/

var config = {
  type: Phaser.AUTO,
  width: window.innerWidth,
  height: window.innerHeight,
  physics: {
      default: 'arcade',
      arcade: {
          gravity: { y: 0 },
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
var score = 0;
var scoreText;
var speedText;
var ballSize = 100;
var ballColor = 0xff0000;
var initialSpeed = 200;
var menu;
var buttonRect;

/**
 * Creates a new game object and initializes its properties and behaviors.
 *
 * @return {void}
 */
function create() {
  var graphics = this.add.graphics();
  var circle = new Phaser.Geom.Circle(ballSize, ballSize, ballSize);
  graphics.fillStyle(ballColor);
  graphics.fillCircleShape(circle);

  var textureName = 'ballTexture';
  graphics.generateTexture(textureName, ballSize * 2, ballSize * 2);
  graphics.destroy();

  ballShadow = this.add.graphics();
  ballShadow.fillStyle(0xffffff, 1);
  ballShadow.fillCircle(window.innerWidth / 2, window.innerHeight / 2, ballSize);

  ball = this.physics.add.image(window.innerWidth / 2, window.innerHeight / 2, textureName);

  ball.setCollideWorldBounds(true);
  ball.setBounce(1, 1);
  ball.setVelocity(0, 0);

  scoreText = this.add.text(window.innerWidth / 2, window.innerHeight / 2, '0', { fontSize: '500px', fill: '#fff', align: 'center' }).setOrigin(0.5);
  scoreText.setDepth(-1);

  // Add red square menu button
  var button = this.add.graphics();
  button.fillStyle(0xff0000);
  button.fillRect(window.innerWidth - 60, window.innerHeight - 60, 50, 50);
  button.setInteractive(new Phaser.Geom.Rectangle(window.innerWidth - 60, window.innerHeight - 60, 50, 50), Phaser.Geom.Rectangle.Contains);

  button.on('pointerdown', openMenu, this);

  // create menu
  menu = this.add.dom(window.innerWidth / 2, 3 * window.innerHeight / 4).createFromHTML('<div id="menu" style="display:none; background-color:white; width:100%; height:30%; position:absolute; bottom:0;"><button style="width:32%;">High Scores</button><button style="width:32%;">Shop</button><button style="width:32%;">Chaos</button></div>');
  
  // Keep a reference to the button's rectangle
  buttonRect = new Phaser.Geom.Rectangle(window.innerWidth - 60, window.innerHeight - 60, 50, 50);
  button.setInteractive(buttonRect, Phaser.Geom.Rectangle.Contains);

  var buttonStyle = 'width:32%; padding:20px; font-size:2em;';
  menu = this.add.dom(window.innerWidth / 2, window.innerHeight + 200).createFromHTML(`
    <div id="menu" style="display:none; background-color:white; width:100%; height:30%; position:absolute; bottom:0;">
      <button style="${buttonStyle}">High Scores</button>
      <button style="${buttonStyle}">Chaos</button>
      <button style="${buttonStyle}">Settings</button>
    </div>
  `);

  // Add event listeners to buttons
  menu.addListener('click');
  menu.on('click', function (event) {
    if (event.target.innerText === 'High Scores') {
      // Handle high scores button click
    } else if (event.target.innerText === 'Chaos') {
      // Handle chaos button click
    } else if (event.target.innerText === 'Settings') {
      // Handle settings button click
    }
  });

  // resize event listener should also update the menu and button position
  window.addEventListener('resize', function(){
    resize();
    menu.x = window.innerWidth / 2;
    menu.y = 3 * window.innerHeight / 4;
    button.clear();
    button.fillStyle(0xff0000);
    button.fillRect(window.innerWidth - 60, window.innerHeight - 60, 50, 50);
  }, false);

  // Add the speed text to the top right of the screen
  speedText = this.add.text(window.innerWidth - 10, 10, 'Speed: 0', { fontSize: '50px', fill: '#fff', align: 'right', fontWeight: 'bold' }).setOrigin(1, 0);

  this.input.on('pointerdown', function (pointer) {
    var dx = pointer.x - ball.x;
    var dy = pointer.y - ball.y;

    if (dx * dx + dy * dy <= ball.width * ball.width) {
        var direction = new Phaser.Math.Vector2(Phaser.Math.Between(-1, 1), Phaser.Math.Between(-1, 1)).normalize();

        if (direction.x !== 0 || direction.y !== 0) {
            if (score === 0) {
                ball.setVelocity(direction.x * 200, direction.y * 200);
            } else {
                var speed = Math.sqrt(ball.body.velocity.x * ball.body.velocity.x + ball.body.velocity.y * ball.body.velocity.y);
                var speedMultiplier = 1.03;
                ball.setVelocity(direction.x * speed * speedMultiplier, direction.y * speed * speedMultiplier);
            }

            score++;
            scoreText.setText(score);
            changeBallProperties.bind(this)();
        }
    } else {
        score = 0;
        scoreText.setText(score);
        ball.setPosition(window.innerWidth / 2, window.innerHeight / 2);
        ball.setVelocity(0, 0);
        resetBallProperties.bind(this)();
    }

}, this);
}

/**
 * Updates the game state by adjusting the speed of the ball and updating the speed text.
 *
 * @return {undefined} There is no return value.
 */
function update() {
  var speed = Math.sqrt(ball.body.velocity.x * ball.body.velocity.x + ball.body.velocity.y * ball.body.velocity.y);
  var maxSpeed = 200 + score * 20;

  if (speed > maxSpeed) {
      ball.body.velocity.x *= maxSpeed / speed;
      ball.body.velocity.y *= maxSpeed / speed;
  }

  // Update the speed text
  speedText.setText('Speed: ' + Math.round(speed));

  ballShadow.clear();
  ballShadow.fillStyle(0xffffff, 1);
  ballShadow.fillCircle(ball.x + 10, ball.y + 10, ball.displayWidth / 2);

  // Check if the ball is within the button
  if (Phaser.Geom.Rectangle.ContainsPoint(buttonRect, ball)) {
    ball.setTint(0xff0000);
  } else {
    ball.clearTint();
  }

}

/**
 * Resizes the game to fit the current window dimensions.
 *
 * @return {undefined} No return value.
 */
function resize() {
  var w = window.innerWidth;
  var h = window.innerHeight;

  game.renderer.resize(w, h);
  game.physics.world.setBounds(0, 0, w, h);

  ball.setPosition(w / 2, h / 2);
  scoreText.setPosition(w / 2, h / 2);

  // Update position of speed text
  speedText.setPosition(w - 10, 10);
}

/**
 * Updates the properties of the ball.
 *
 * @param {type} paramName - description of parameter
 * @return {type} description of return value
 */
function changeBallProperties() {
  ballSize *= 0.98;
  ballColor = Phaser.Display.Color.RandomRGB().color;

  var graphics = this.add.graphics();
  graphics.fillStyle(ballColor);
  graphics.fillCircle(ballSize, ballSize, ballSize);
  var textureName = 'ballTexture' + score;
  graphics.generateTexture(textureName, ballSize * 2, ballSize * 2);
  graphics.destroy();

  ball.setTexture(textureName);
  ball.displayWidth = ballSize * 2;
  ball.displayHeight = ballSize * 2;
  
  // Adjust the ball's body size after changing its dimensions
  ball.body.setSize(ball.displayWidth, ball.displayHeight);

  ballShadow.clear();
  ballShadow.fillStyle(0xffffff, 1);
  ballShadow.fillCircle(ball.x + 10, ball.y + 10, ball.displayWidth / 2);

  ball.setTint(0xffffff);
  setTimeout(function() {
      ball.clearTint();
  }, 250);
}

/**
 * Resets the properties of the ball.
 *
 * @return {void} 
 */
function resetBallProperties() {
  ballSize = 100;
  ballColor = 0xff0000;
  ball.clearTint();
  
  var graphics = this.add.graphics();
  graphics.fillStyle(ballColor);
  graphics.fillCircle(ballSize, ballSize, ballSize);
  var textureName = 'ballTexture';
  graphics.generateTexture(textureName, ballSize * 2, ballSize * 2);
  graphics.destroy();

  ball.setTexture(textureName);
  ball.displayWidth = ballSize * 2;
  ball.displayHeight = ballSize * 2;

  ballShadow.clear();
  ballShadow.fillStyle(0xffffff, 1);
  ballShadow.fillCircle(ball.x + 10, ball.y + 10, ball.displayWidth / 2);
}

/**
 * Toggles the display of the menu and slides the game area up or down accordingly.
 *
 * @return {undefined} This function does not return a value.
 */
function openMenu() {
  var menuDisplay = menu.node.style.display === "none";
  menu.node.style.display = menuDisplay ? "block" : "none";

  if (menuDisplay) {
    // Slide the game area up to reveal the menu
    this.tweens.add({
      targets: this.cameras.main,
      y: -window.innerHeight * 0.3,
      duration: 1000,
      ease: 'Power2'
    });
  } else {
    // Slide the game area down to hide the menu
    this.tweens.add({
      targets: this.cameras.main,
      y: 0,
      duration: 1000,
      ease: 'Power2'
    });
  }

  resize();
}