var gulp = require('gulp');
var sass = require('gulp-sass');
var minifycss = require('gulp-minify-css');
var prefixer = require('gulp-autoprefixer');
var rename = require('gulp-rename');
var notify = require('gulp-notify');

gulp.task('sass', function () {
    return gulp
        .src('scss/spectre-css.scss')
        .pipe(sass())
        .pipe(prefixer({ browsers: ['> 0%'] }))
        .pipe(rename('spectre.css'))
        .pipe(gulp.dest('./dist/css/'))
        .pipe(minifycss())
        .pipe(rename('spectre.min.css'))
        .pipe(gulp.dest('./dist/css/'))
        .pipe(notify({message: 'Sass compiled!', onLast: true}));
});

gulp.task('watch', function() {
    gulp.watch('scss/*.scss', ['sass']);
});