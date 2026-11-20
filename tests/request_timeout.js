const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require.resolve('../static/js/app.js'),'utf8');
const start = source.indexOf('  async function api(path, options = {})');
const end = source.indexOf('  async function apiRequest(',start);
assert.ok(start>=0 && end>start);
class ApiError extends Error { constructor(message,status,code){super(message);this.status=status;this.code=code;} }
(async()=>{
 let signal;
 const context = vm.createContext({AbortController,ApiError,setTimeout,clearTimeout,apiRequest:async (path,options)=>{signal=options.signal;return new Promise(()=>{});}});
 vm.runInContext(source.slice(start,end),context);
 await assert.rejects(context.api('/api/v1/mcp/setup',{timeoutMs:15}),error=>error.status===408 && error.code==='request_timeout');
 assert.equal(signal.aborted,true,'timed-out fetch must also be cancelled');
 context.apiRequest=async()=>({transport:'stdio'});
 assert.equal((await context.api('/api/v1/mcp/setup',{timeoutMs:100})).transport,'stdio');
 const forbidden=new ApiError('permission denied',403,'forbidden');
 context.apiRequest=async()=>{throw forbidden};
 await assert.rejects(context.api('/api/v1/mcp/setup',{timeoutMs:100}),error=>error===forbidden);
 context.apiRequest=async(path,options)=>({path,options});
 const response=await context.api('/api/v1/vms',{method:'POST',body:{name:'test'}});
 assert.equal(response.options.timeoutMs,undefined);
 assert.equal(response.options.signal,undefined,'long mutations must retain their existing behavior');
 console.log('Bounded setup requests cancel stalled fetches, preserve permission errors, and leave long mutations unchanged');
})().catch(error=>{console.error(error);process.exitCode=1});
