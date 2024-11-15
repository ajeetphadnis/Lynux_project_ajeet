/* link to code: https://geshan.com.np/blog/2021/07/rabbitmq-docker-nodejs/
 * command to start rabbitmq server: docker run -p 15672:15672 -p 5672:5672 --name rabbit-image-name rabbitmq:management
 * FAQ: What is the max size of one single message in RabbitMQ?
 * While the theoretical message size limit in RabbitMQ is 2GB up to 3.7.0, we don't recommend sending messages larger than 128MB, which is also the new max size limit in 3.8.0 and onward. Large messages are especially problematic when using mirrored queues in HA clusters and can cause memory and performance issues.
 * References:
 * https://github.com/rabbitmq/rabbitmq-server/issues/147#issuecomment-470882099
 * https://github.com/rabbitmq/rabbitmq-common/pull/289.
 *
 *  Author: Ajeet Phadnis
 * 
 */

const amqplib = require('amqplib');
const amqpUrl = process.env.AMQP_URL || 'amqp://test:test@localhost:5672';


/**
 * Function: publisher
 * This function takes the messages from user and creates rabbitmq conneciion
 * exchange, queue and routingkey and sends the message to queue.
 */
(async () => {
  const connection = await amqplib.connect(amqpUrl, 'heartbeat=60');
  const channel = await connection.createChannel();
  try {
    console.log('Publishing');
    const exchange = 'user.signed_up';
    const queue = 'user.sign_up_email';
    const routingKey = 'sign_up_email';
    
    await channel.assertExchange(exchange, 'direct', {durable: true});
    await channel.assertQueue(queue, {durable: true});
    await channel.bindQueue(queue, exchange, routingKey);
    
    const msg = {'id': Math.floor(Math.random() * 1000), 'email': 'user@domail.com', name: 'Ajeet Phadnis'};
    await channel.publish(exchange, routingKey, Buffer.from(JSON.stringify(msg)));
    console.log('Message published');
  } catch(e) {
    console.error('Error in publishing message', e);
  } finally {
    console.info('Closing channel and connection if available');
    await channel.close();
    await connection.close();
    console.info('Channel and connection closed');
  }
  process.exit(0);
})();