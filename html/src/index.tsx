import 'whatwg-fetch';
import { h, render } from 'preact';
import { LoginForm } from './components/app';
import './style/index.scss';

render(<LoginForm />, document.body);
