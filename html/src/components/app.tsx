import { h, Component } from 'preact';

import { ITerminalOptions, ITheme } from 'xterm';
import { Xterm } from './terminal';
import linkState from 'linkstate';

if ((module as any).hot) {
    // tslint:disable-next-line:no-var-requires
    require('preact/debug');
}

function getQueryParams(qs) {
    qs = qs.split('+').join(' ');
    var params = {},
        tokens,
        re = /[?&]?([^=]+)=([^&]*)/g;
    while (tokens = re.exec(qs)) {
        params[decodeURIComponent(tokens[1])] = decodeURIComponent(tokens[2]);
    }
    return params;
}

const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const path = window.location.pathname.replace(/[\/]+$/, '');
const wsUrl = [protocol, '//', window.location.host, path, '/ws', window.location.search].join('');
const tokenUrl = [window.location.protocol, '//', window.location.host, path, '/token'].join('');
let qparams = getQueryParams(document.location.search);
const termOptions = {
    fontSize: 13,
    fontFamily: 'Menlo For Powerline,Consolas,Liberation Mono,Menlo,Courier,monospace',
    theme: {
        foreground: '#d2d2d2',
        background: '#2b2b2b',
        cursor: '#adadad',
        black: '#000000',
        red: '#d81e00',
        green: '#5ea702',
        yellow: '#cfae00',
        blue: '#427ab3',
        magenta: '#89658e',
        cyan: '#00a7aa',
        white: '#dbded8',
        brightBlack: '#686a66',
        brightRed: '#f54235',
        brightGreen: '#99e343',
        brightYellow: '#fdeb61',
        brightBlue: '#84b0d8',
        brightMagenta: '#bc94b7',
        brightCyan: '#37e6e8',
        brightWhite: '#f1f1f0',
    } as ITheme,
} as ITerminalOptions;

interface AuthToken {
    token: string;
}

export class App extends Component<AuthToken> {
    render() {
        return <Xterm id="terminal-container" authToken={this.props.token} wsUrl={wsUrl} tokenUrl={tokenUrl} options={termOptions} />;
    }
}

export class LoginForm extends Component {
    state = {
        username: '',
        password: '',
        qtoken: '',
        token: ''
    };
    login = async () => {
        let { username, password, token } = this.state;
        if(username!=='' && password!=='') {
            const resp = await fetch(tokenUrl, { 
                method: "GET",
                headers: {
                    "logincreds": btoa(username+":"+password),
                }
            });
            if (resp.ok) {
                const json = await resp.json();
                this.setState({token: json.token});
            }
        }
    };
    qlogin = async () => {
        const resp = await fetch(tokenUrl+document.location.search);
        if (resp.ok) {
            qparams = {};
            const json = await resp.json();
            this.setState({token: json.token});
        } else {
            document.location.href = "";
        }
    };
    render({}, {}) {
        const valid = this.state.token!==undefined && this.state.token!=='';
        if(valid) {
            return <App token={this.state.token} />;
        }
        if(document.location.search && document.location.search.length>1 && Object.keys(qparams).length>0) {
            this.qlogin();
            return <div>Loading...</div>;
        }
        return (
            <div class="formContainer" style="display:flex;justify-content:center;align-items:center;height:80vh;margin:0;">
                <form class="form-inline" onSubmit={this.login} action="javascript:">
                <label for="name">User Name:</label>
                <input type="text" onInput={linkState(this, 'username')} placeholder="Enter User Name" style="padding:5px; margin:0 5px;"/>
                <label for="pwd">Password:</label>
                <input type="password" onInput={linkState(this, 'password')} placeholder="Enter Password" style="padding:5px;margin:0 5px"/>
                <button type="submit" style="padding:6px;cursor:pointer;background-color:#1e90ff;color:#fff;border:1px solid #ddd;">Login</button>
                </form>
            </div>
        );
    }
}
