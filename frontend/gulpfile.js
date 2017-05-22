var gulp = require('gulp');

// List plugins
var gulp = require('gulp');
var concat = require('gulp-concat');
var del = require('del');
var htmlmin = require('gulp-htmlmin');
var lib = require('bower-files')();
var imagemin = require('gulp-imagemin');
var pngquant = require('imagemin-pngquant');
var minifyCSS = require('gulp-minify-css');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var livereload = require('gulp-livereload');
var rename = require('gulp-rename');
var git = require('git-rev-sync');
var replace = require('gulp-replace');
var gulpif = require("gulp-if");
var ngAnnotate = require('gulp-ng-annotate');


// Define paths
var paths = {
  clean: {
    src: 'dist/**/*'
  },
  favicon: {
      src: ['app/favicon.ico'],
      dest: 'dist/'
  },
  images: {
  src: 'app/images/*',
  dest: 'dist/images'
  },
  scripts: {
    src: ['app/scripts/**/*.js'],
    dest: {
      dev: 'app/scripts',
      dist: 'dist/scripts'
    },
    watch: ['app/scripts/**/*.js', 'app/scripts/scripts.js']
  },
  html: {
    src: {
      base: ['app/*.html'],
      views: ['app/views/*.html'],
      watch: ['app/*.html', 'app/views/*.html']
    },
    dest: {
      base: 'dist',
      views: 'dist/views'
    }
  },
  css: {
      src: ['app/styles/*.css'],
      dest: 'dist/styles'
  },
  dependencies: {
    dest: {
      dev: 'app/bower_components',
      dist: 'dist/bower_components'
    }
  }
};

// Remove files in dist folder
gulp.task('clean', function () {
  del(paths.clean.src);
});


// Concatenate and minify script files with debug info
gulp.task('scripts', function () {
  gulp.src(paths.scripts.src)
     .pipe(sourcemaps.init())
      .pipe(ngAnnotate())
      .pipe(concat('scripts.min.js'))
     .pipe(sourcemaps.write())
    .pipe(gulp.dest(paths.scripts.dest.dist));
});

// Minify HTML files
gulp.task('html', function () {
  gulp.src(paths.html.src.base)
    .pipe(gulp.dest(paths.html.dest.base));

  gulp.src(paths.html.src.views)
    .pipe(gulp.dest(paths.html.dest.views));
});

// Minify css files
gulp.task('css', function () {
    gulp.src(paths.css.src)
        .pipe(minifyCSS({
            keepBreaks: true
        }))
        .pipe(gulp.dest(paths.css.dest));
});

// Minify images
gulp.task('images', function () {
  return gulp.src(paths.images.src)
    .pipe(imagemin({
      progressive: true,
      svgoPlugins: [
        {
          removeViewBox: false
        }
      ],
      use: [
        pngquant()
      ]
    }))
    .pipe(gulp.dest(paths.images.dest));
});

// Copy client dependencies
gulp.task('dependencies', function () {
  gulp.src(lib.ext('js').files)
    .pipe(concat('lib.min.js'))
    .pipe(gulp.dest(paths.dependencies.dest.dist));

  gulp.src(lib.ext('css').files)
    .pipe(concat('lib.min.css'))
    .pipe(gulp.dest(paths.dependencies.dest.dist));
});

// Watch files
gulp.task('watch', function () {
  gulp.watch(paths.scripts.watch, ['scripts']);
  gulp.watch(paths.html.src.watch, ['html']);
  gulp.watch(paths.css.src, ['css']);
  livereload({ start: true });
   console.log('Watcher started');
});


// Run `gulp build` to update developer and client environments
gulp.task('build', ['scripts', 'html', 'css', 'images', 'css', 'watch']);

// Run `gulp lib` to build minified client dependencies
gulp.task('lib', ['dependencies']);
