import argparse
import logging
import os
from multiprocessing import Process
from time import sleep

import wazuh_testing.tools.agent_simulator as ag
from wazuh_testing import TCP

logging.basicConfig(level=logging.DEBUG)


def run_agents(agents_number=1, manager_address='localhost', protocol=TCP, agent_version='v4.0.0',
               agent_os='debian8', eps=1000, run_duration=20, active_modules=[], modules_eps=None):
    """Run a batch of agents connected to a manager with the same parameters.

    Args:
        agents_number (int): Number of agents to run.
        manager_address (str): Manager address (hostname or IP).
        protocol (str): Communication protocol.
        agent_version (str): Agents version p.e: v4.0.0
        agent_os (str): Agents os, some examples: debian8, ubuntu18.04, mojave...
        eps (int): Total events per second sent by each agent to the manager.
        run_duration (int): Agent life time.
        active_modules (list): list with active modules names.
        modules_eps (list): list with eps for each active modules.
    """

    logger = logging.getLogger(f"P{os.getpid()}")
    logger.info(f"Starting {agents_number} agents.")

    active_agents, injectors = [], []


    for _ in range(agents_number):
        agent = ag.Agent(manager_address, "aes", os=agent_os, version=agent_version, fim_eps=eps)
        available_modules = agent.modules.keys()
        sending_modules = len(active_modules)
        if 'receive_messages' in active_modules:
            sending_modules -= 1
        for index, module in enumerate(available_modules):
            if module in active_modules:
                agent.modules[module]['status'] = 'enabled'
                if modules_eps is not None and 'eps' in agent.modules[module]:
                    agent.modules[module]['eps'] = modules_eps[index]
                else:
                    agent.modules[module]['eps'] = eps/sending_modules
            else:
                agent.modules[module]['status'] = 'disabled'
                agent.modules[module]['eps'] = 0

        for module in active_modules:
            if module not in available_modules:
                raise ValueError(f"Selected module: '{module}' doesn't exist on agent simulator!")

        logger.info(agent.modules)

        active_agents.append(agent)
        sender = ag.Sender(manager_address, protocol=protocol)
        injectors.append(ag.Injector(sender, agent))

    try:
        start(injectors)
        sleep(run_duration)
    finally:
        stop(injectors)


def start(agent_injectors):
    print(f"Running {len(agent_injectors)} injectors...")
    for injector in agent_injectors:
        injector.run()


def stop(agent_injectors):
    print(f"Stopping {len(agent_injectors)} injectors...")
    for injector in agent_injectors:
        injector.stop_receive()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-a', '--manager', metavar='<manager_ip_address>', type=str, required=False,
                            default='localhost', help='Manager IP address', dest='manager_addr')

    arg_parser.add_argument('-e', '--eps', metavar='<events_per_second>', type=int, required=False, default=1000,
                            help='Number of events per second to be generated by each agent', dest='eps')

    arg_parser.add_argument('-n', '--agents', metavar='<agents_number>', type=int, default=5, required=False,
                            help='Number of agents to create and run', dest='n_agents')

    arg_parser.add_argument('-b', '--batch', metavar='<agents_batch>', dest='b_agents',
                            type=int, required=False, default=2, help='Number of agents to create on each process')

    arg_parser.add_argument('-o', '--os', metavar='<os>', dest='os',
                            type=str, required=False, default='debian8', help='Agent operating system',)

    arg_parser.add_argument('-p', '--protocol', metavar='<protocol>', dest='agent_protocol',
                            type=str, required=False, default=TCP, help='Communication protocol')

    arg_parser.add_argument('-t', '--time', metavar='<monitoring_time>', dest='duration',
                            type=int, required=False, default=20, help='Time in seconds for monitoring')

    arg_parser.add_argument('-v', '--version', metavar='<version>', dest='version',
                            type=str, required=False, default='4.2.0', help='Agent wazuh version', )

    arg_parser.add_argument('-m', '--modules', dest='modules', required=False, type=str, nargs='+', action='store',
                            default=['fim'], help='Active module separated by whitespace.')

    arg_parser.add_argument('-s', '--modules-eps', dest='modules_eps', required=False, type=int, nargs='+',
                            action='store', default=None, help='Active module EPS separated by whitespace.')

    args = arg_parser.parse_args()

    if args.b_agents > 2:
        logging.warning("Launching more than 2 agents per process is not advisable as Python's GIL dramatically "
                        "reduces the performance of the agent_simulator tool when there are multiple agents running in "
                        "the same process.")

    # Calculate modules EPS
    if args.modules is not None and args.modules_eps is not None:
            len_mod = len(args.modules)
            len_eps = len(args.modules_eps)
            if len_mod != len_eps:
                arg_parser.error(f"Wrong number of eps introduced for selected modules:{len_eps}, expected:{len_mod}.")

    # Calculate agents per process
    remainder = args.n_agents % args.b_agents
    n_processes = args.n_agents // args.b_agents + (1 if remainder != 0 else 0)

    processes = []

    for i in range(n_processes):
        agents = args.b_agents
        if remainder != 0 and i == 0:
            agents = remainder

        arguments = (
            agents, args.manager_addr, args.agent_protocol, args.version, args.os, args.eps, args.duration,
            args.modules, args.modules_eps
        )

        processes.append(Process(target=run_agents, args=arguments))

    for p in processes:
        p.start()

    for p in processes:
        p.join()
